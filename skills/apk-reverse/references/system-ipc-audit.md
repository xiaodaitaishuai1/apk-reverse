# System IPC audit — Binder, Intent, WebView, SELinux, attestation

Load this when the question is not "what code does the app run" but **"what does the app ask the
system to do, and who answers"**: you need to see the app's Binder traffic to a system service,
decide whether a behaviour is decided by an Intent/JS-bridge input you can control, understand a
`service call` transaction code, get past an `avc: denied` that is blocking your instrumentation,
or reason about a Keystore attestation check that is flagging your rooted device. This file is the
system-side complement to `references/dynamic-frida.md` §Hook strategy (in-process observation) and
`references/protocol-reverse.md` (the app's own network wire): those own the app's traffic, this one
owns the platform boundary it talks to.

**Strength note, read this first:** nothing in this file was run end to end by this repository's
verification passes — no Binder hook, no `service call` probe, no attestation parse was executed
against a sample here. The commands and hook scripts are absorbed from an external notes site
(milksu.org, Android internals notes, retrieved 2026-10-19) and are **unverified** in the sense of
`references/coverage-and-limits.md` §Strength labels: reported by someone else, not reproduced here.
The platform *mechanisms* they rest on — AIDL codegen arithmetic, `FIRST_CALL_TRANSACTION`,
kernel-filled caller identity, `FLAG_IMMUTABLE` being mandatory since Android 12, the attestation
extension fields — are **inferred**: they follow from documented AOSP behaviour the notes cite, and
each is the kind of fact that fails loudly if wrong (a wrong transaction code returns an error, not
a silent miss). Treat the scripts as starting points to verify on your own device, not as measured
procedures, and label your own results the same way.

## 1. Binder — seeing the app's calls into system_server

The app's privileged actions (install, start components, clipboard, location) cross the Binder
boundary, and the *server* side re-checks identity there: `Binder.getCallingUid()/getCallingPid()`
is filled in by the binder driver from the calling task, **not** copied from the parcel, so it is
not spoofable from the client side (inferred from the driver's documented behaviour). Two practical
consequences: you cannot fake another app's UID by crafting a parcel — and read the value with the
right semantics for *where* you hooked. In the **app's own process** `getCallingUid()` is the app's
own uid except while serving an inbound transaction; a callback relayed by system_server after its
own `clearCallingIdentity()` arrives as **uid 1000** — the classic "the system is calling my app!"
misread, when it is a relayed callback carrying the server's identity.

**Transaction codes.** AIDL generates `TRANSACTION_<method> = FIRST_CALL_TRANSACTION + n` with
`FIRST_CALL_TRANSACTION = 1` (inferred from the codegen contract) — but **read the constants, do	not count the `.aidl`**: classic codegen ordering and the on-device generated Stub are the ground
truth, and they only coincide with the AOSP-tag `.aidl` you happen to be reading (OEMs patch
them; stable AIDL freezes ordinals append-only, framework interfaces move every release). The
one-line runtime read: `Java.use("<iface>$Stub").TRANSACTION_<method>.value`.

**Observing outbound traffic (client side, in the target app's process):**

```javascript
// unverified — absorbed from milksu.org notes, not run by this repo
Java.perform(function() {
    var BP = Java.use("android.os.BinderProxy");
    BP.transact.implementation = function(code, data, reply, flags) {
        console.log("[Binder] " + this.getInterfaceDescriptor() + " code=" + code);
        return this.transact(code, data, reply, flags);
    };
});
```

`getInterfaceDescriptor()` names the service, `code` names the method — together they are the
"which privileged call, with which arguments" record that static analysis of the app alone cannot
give you when the call site is behind a SDK facade. For inbound traffic (something calling *into*
the app — an exported service, a callback interface), hook `android.os.Binder.execTransact` the
same way (signature `(int, long, long, int)` on O+). When the interface is known, hooking the
**generated proxy method instead of the raw transact** gives you decoded Java arguments — a live
example is `Java.use("android.content.pm.IPackageManager$Stub$Proxy").getPackageInfo`, already
this skill's own hook target in `references/detection-and-anti-analysis.md`; installs transit
`IPackageInstallerSession$Stub$Proxy.commit`. No parcel parsing. The raw hook tells you *that* a
call crossed; the proxy hook tells you *what it meant*.

*(Provenance note: the source article's version of the outbound script hooks
`android.os.Binder.transact` and calls `getCallingUid()` inside it — server-side semantics in a
client-side hook. The form here is corrected accordingly; only its provenance is external.)*

Root-level state, for the "why does my hook never fire" question: `adb shell su -c 'cat
/sys/kernel/debug/binder/proc/<pid>'` (on binderfs/GKI kernels, ~Android 12+, the same log lives
under `/sys/kernel/debug/binderfs/binder_logs/`) lists the process's binder threads, the nodes
(objects it serves) and the refs (objects it holds) — zero nodes means the process never
registered the service you are trying to reach, and no client-side hook will ever fire. *(unverified
— absorbed from milksu.org notes, retrieved 2026-10-19)*

**Hook-point map** — hook the funnel, not the hop; funnel names outlive every hop rename below.
*(unverified — absorbed from milksu.org notes, retrieved 2026-10-19)*

| Reversing question | The funnel (app-side, stable) | The hop it actually transits | Verify with |
|---|---|---|---|
| app starts a component | `Activity#startActivity` / `ContextImpl#startService` | `IActivityManager`, then **ATMS** — `ActivityTaskManager` facade since Android 10, `IActivityTaskManager` interface since 11 | `dumpsys activity` |
| app installs/updates itself | `PackageInstaller#Session#commit` | `IPackageInstallerSession` binder from the `createSession` **reply** — not from ServiceManager, so `service call` cannot reach it | hook-or-nothing by construction |
| package info / signature query | `PackageManager#getPackageInfo` | `IPackageManager$Stub$Proxy#getPackageInfo` (`GET_SIGNATURES` 64 deprecated P+ → `GET_SIGNING_CERTIFICATES`) | `dumpsys package <pkg>` |
| permission state | `ContextImpl#checkSelfPermission` | server side split into `PermissionManagerService` (11+) | `dumpsys package <pkg>` |
| clipboard | `ClipboardManager#set/getPrimaryClip` | `IClipboard$Stub$Proxy` (`clipboard`) | descriptor |
| unknown outbound call | `BinderProxy#transact` (script above) | — | `getInterfaceDescriptor()` |
| inbound into the app | the app's own Stub impls / `Binder#execTransact` | — | `getCallingUid()` inside (uid-1000 trap above) |

**Driving a service by hand:** `adb shell service list` enumerates services;
`adb shell service call <service> <code> i32 ... s16 ...` invokes transaction `<code>` directly
(argument type tags: `i32`/`i64`/`f`/`d`/`s16`, plus `null` and `fd`). The interface token is
written for you — never prefix an `s16` descriptor yourself. And it only reaches services in the
default binder context (`/dev/binder`): HAL interfaces live in other contexts and are not
`service call`-able. Use it to confirm a code number against a known method before you build a
hook on it. `adb shell dumpsys binder_calls_stats` (Android 9+; `dumpsys binder_calls_stats enable`
first if empty) shows which binder calls a process actually made — a zero-friction first look
before you hook anything.

## 2. Intent audit — the input channels a repack cannot remove

The app's exported components and deep links are inputs an attacker (and you, when testing) control
without repacking. Three signatures worth grepping a jadx export for, all unverified as to
prevalence but mechanically cheap to check:

| Signature | Meaning |
|---|---|
| `getParcelableExtra("intent"\|"next"\|"redirect"\|"forward")` fed straight to `startActivity`/`sendBroadcast` | Intent redirection: your crafted nested Intent runs with this app's identity and privileges |
| implicit `Intent` sent with sensitive extras and no `setPackage()` | any higher-priority receiver can register for the action and harvest the extras |
| deep link / Intent extra flowing into `loadUrl` or a file path without scheme/host whitelist | injection into the WebView or path traversal surface (next section) |
| `Intent.parseUri(url, URI_INTENT_SCHEME)` fed straight to `startActivity` in `shouldOverrideUrlLoading` | intent-scheme handoff: an unvalidated nested Intent arriving from web content |
| `ClipData` plus `FLAG_GRANT_READ/WRITE_URI_PERMISSION` forwarded to another component | temporary URI grants travelling further than the app intended |

`PendingIntent` without `FLAG_IMMUTABLE` (mandatory to *declare* either flag since Android 12 —
inferred from the platform change) is the same class of bug with a capability token: a mutable
PendingIntent handed to an untrusted party lets them rewrite the inner Intent.

**Driving an exported component mid-task** — no hook needed: `adb shell am start -a <action> -d
<uri> --es k v` and `adb shell am broadcast -a <action> --es k v` (action/data/extras forms;
`cmd package resolve-activity -a <action> -d <uri>` resolves the receiver first).

**The Intent monitor** *(both unverified — absorbed from milksu.org notes, retrieved 2026-10-19)*:
wrap `Activity.startActivity`, `ContextImpl.sendBroadcast` and `startService`; print action, data,
component and every extra, and flag any extra whose value is itself an `Intent` — the redirection
signature caught live, with the caller stack one `Log.getStackTraceString` away. Its deep-link
counterpart hooks `Intent.getData` and flags `..`, `file://`, `intent://` in the returned URI —
traversal and scheme-abuse inputs without a full monitor.

## 3. WebView and the JS bridge — audit surface and probing channel

The bridge is not just a risk surface: it is a **probe the app ships for you**. A bridge method is
a Java entry point callable without writing a hook, and its return values, errors, and logcat
echoes are oracles into the app's core logic. The flow below moves from static width to active
probing; sanctioned scope is probing the app's own bridge from a page the app loads — no renderer
sandbox-escape work.

**3.1 Config width (static).** Grep a jadx export; the defaults column decides what *absence* means.
*(Defaults verified against frameworks/base `core/java/android/webkit/WebSettings.java` and
`WebView.java` javadoc via the cnb.cool AOSP mirror, 2026-10-19.)*

| Setting | Effect if `true` | Default |
|---|---|---|
| `setAllowUniversalAccessFromFileURLs` | a `file://` page can read any origin — the app's private files included | **false since API 16**; deprecated — an explicit `true` in jadx is required for the exfil chain on any modern target |
| `setAllowFileAccessFromFileURLs` | `file://` pages can read other `file://` URLs | same: false since 16, deprecated |
| `setAllowFileAccess` | `file://` loadable at all | **true up to targetSdk 29 (Q), false from 30 (R)** — absence is not "off" on a ≤29 app |
| `setAllowContentAccess` | `content://` loadable | true |
| `setJavaScriptEnabled` | the base widening — required by most bridges, rarely the finding itself | false |
| `setDomStorageEnabled` | web-side state under `/data/data/<pkg>/app_webview/` — where tokens often live | false |
| `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)` | plain-HTTP subresources readable without any TLS fight (`references/tls-and-cert.md`) | NEVER_ALLOW on ≥21 |
| `setWebContentsDebuggingEnabled` | **a free remote-debug entry for you** — see 3.4 | false; **auto-enabled for `android:debuggable` apps on WebView 113.0.5656.0+** (javadoc, same verification) |

**3.2 Bridge inventory (hook, corrected).** Since API 17 the injected object exposes only public
methods annotated `@JavascriptInterface` — for apps *targeting* API ≤16 **all public methods** are
exposed (javadoc-verified, same source). So tag the inventory:

```javascript
// unverified — absorbed from milksu.org notes, corrected with the annotation filter
var WV = Java.use('android.webkit.WebView');
var JI = Java.use('android.webkit.JavascriptInterface').class;
WV.addJavascriptInterface.implementation = function(obj, name) {
    console.log('[WV] bridge: ' + name + ' -> ' + obj.getClass().getName());
    var ms = obj.getClass().getDeclaredMethods();
    for (var i = 0; i < ms.length; i++)
        console.log('   ' + (ms[i].getAnnotation(JI) !== null ? '[exposed] ' : '[internal] ')
                    + ms[i].getName());
    return this.addJavascriptInterface(obj, name);
};
```

On a targetSdk<17 app the unfiltered list is the truth. The same one-liner shape on
`WebView.loadUrl.overload('java.lang.String')` records every URL opened — the dynamic counterpart
of the `loadUrl` grep row in `references/recon.md` §5. Note which bridges never transit this hook:
URL-scheme interception (`shouldOverrideUrlLoading` parsing a custom scheme) and the
`WebMessageListener`/`postWebMessage` message family — grep for both in the jadx export.

**3.3 The probing playbook** — run from the app's own page, pasted from `chrome://inspect` or from
a probe page the app is made to load (deep link / `am start --es url`):

1. **Global diff** — `Object.getOwnPropertyNames(window)` filtered for
   `/bridge|android|native|jsb|hybrid|weixin|alipay/i`. A non-standard global names the SDK and
   routes to vendor identification; `typeof window[k] !== 'undefined'` is the cheapest existence
   oracle there is.
2. **Dictionary probe** — enumeration of the injected object usually returns `[]` on modern
   WebView (non-enumerable methods), so make the *dictionary* primary: method names harvested from
   the jadx bridge class (3.2), from the bundled front-end JS (`assets/www/*.js`, every
   `window.bridge.x(` call site), and from known SDK globals. `typeof o[m]` per candidate:
   `'function'` = exposed, `undefined` = not.
3. **Arity/type oracle** — call with `[]`, with extra args, with non-coercible types; extra args
   are ignored, missing args arrive as null/defaults, and the error surfaces in the **console
   channel or logcat, not necessarily as a JS exception** — so run the probe with
   `adb logcat -s chromium Console` watching alongside. A Java-side exception stack in logcat can
   name the handler class **without any hook**. (Console relay requires the app not to have
   overridden `WebChromeClient` without relaying — `inferred`; if the channel is dead, that is
   itself a finding.)
4. **Return oracle** — `undefined` vs `void` is ambiguous until calibrated: call a bridge method
   the jadx export shows returning `void`, record what JS actually receives, and unknown returns
   become interpretable. For async message bridges, probe args named `callback`/`cb` and watch for
   the response arriving on an injected `window.__*` object (discoverable by step 1).
5. **Origin gate** — a bridge that silently no-ops from your page but works from the app's own
   page is an origin check: record it, and probe from a page origin the app trusts instead.

Then route to Java: method name → jadx string cross-ref (`recon.md` §6) → the
`@JavascriptInterface` method → owning class → ordinary Java hook (`dynamic-frida.md`). The hook in
3.2 names the class for `addJavascriptInterface` bridges; for the other two bridge shapes the
static grep row is the entry.

**3.4 DevTools entry.** Two channels, different plumbing: `chrome://inspect` does its own adb
discovery and needs no forward; the manual route is for direct HTTP — find the socket first
(`adb shell cat /proc/net/unix | grep devtools`; the name `webview_devtools_remote_<pid>` carries
the pid), then `adb forward tcp:9222 localabstract:webview_devtools_remote_<pid>` and read
`http://localhost:9222/json`. The switch is **static and process-wide** — every WebView in the
process, not per-instance — and auto-enabled on debuggable apps from WebView 113
(javadoc-verified, 3.1). When it is off and no debuggable flag, `adb logcat | grep Console`
(`I/chromium ... [INFO:CONSOLE(n)]`) is the fallback observation channel — if the app has not
overridden the chrome client without relaying.

## 4. SELinux — when it blocks *your* tools, not the app

`avc: denied` lines in logcat/dmesg carry four useful fields: `scontext` (who), `tcontext` (what),
`tclass` (class), and the requested permission. When frida-server or a pushed binary will not run,
this is the usual cause — the file's context does not permit execution from the domain that tried.
The notes' remediation sequence, unverified here: read the denial, then either relabel/relocate the
binary, or generate the exact allow rule with `adb shell dmesg | audit2allow -p sepolicy.bin` after
pulling the policy from `/sys/fs/selinux/policy`, and audit what it emits before applying it
(`audit2allow` is deliberately over-broad). For *reading* what an app domain may do,
`sesearch -A -s untrusted_app sepolicy.bin` answers "can this app even reach X" questions that
save a hook that could never fire. For the measured frida-server execution denial specifically,
the live one-line fix is `magiskpolicy --live "allow <domain> <type> file execute"` — or run the
binary in a different domain altogether.

The same policy file answers the *explain-the-target* half — why the app reaches something you
thought was closed: query wildcard grants (`sesearch -A -s <domain> -t <type>` — an `allow … *`
row like `system_app vendor_data_file:file *` is the one-line explanation for "why can this
preinstalled app read vendor data"), attribute memberships (`seinfo -t <type> -x`), and missing
`type_transition` rules. A policy read explains the behaviour without touching the running
system — and that is the boundary: reading the target's policy to explain it is in scope;
injecting rules or flipping enforcement to defeat it is root-framework development, not this
skill. *(unverified — absorbed from milksu.org notes, retrieved 2026-10-19)*

## 5. Keystore attestation — the check that survives client-side patching

Key attestation returns a certificate chain (Google root → device key → per-key cert) whose
extension records `verifiedBootState`, `deviceLocked`, and the security level (Software / TEE /
StrongBox). An app that ships this and *verifies it server-side* has a root/bootloader-unlock
detector you cannot satisfy by patching the client — the honest routes are a device that passes,
or finding the server-side decision and what it actually gates. What you *can* observe client-side:
hook `android.security.keystore.KeyGenParameterSpec$Builder.build` and
`java.security.KeyStore.getEntry` to see aliases, purposes, and whether user-auth binding is
requested — that tells you whether the app leans on hardware keys at all before you spend time on
the harder question.

Reading a dumped chain: the leaf certificate's attestation extension (OID 1.3.6.1.4.1.11129.2.1.17,
a `KeyDescription` sequence) splits every claim into `softwareEnforced` and `teeEnforced` halves —
the same claim in both halves is the tell for a software-only implementation, and a
`teeEnforced`-only key property means the key material never exists in the app's process, which
decides the extraction question before you spend a process window on it. *(unverified — absorbed
from milksu.org notes, retrieved 2026-10-19)* This is the boundary case for
`references/detection-and-anti-analysis.md` §Step 3: locating the check — the order of search: the
check runs outside the process, so in-process stages cannot reach it.

## 6. Where this hands off

- App's own network traffic (the wire, not the platform): `references/protocol-reverse.md`
- TLS/certificate failures on one feature: `references/tls-and-cert.md` §If OkHttp is the failing path
- Hooking environment and strategy: `references/dynamic-frida.md` §Hook strategy
- Detection that fires before your hooks exist: `references/detection-and-anti-analysis.md` §Step 3: locating the check — the order of search
