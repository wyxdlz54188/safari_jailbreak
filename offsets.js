const offsets_obj = {

    memPoolStart: undefined,
    memPoolEnd: undefined,

    __ZZ6dlopenE1p: undefined,
    dlopen_internal: undefined,
    __ZL25sNotifyMonitoringDyldMain: undefined,
    __ZN4dyldL24notifyMonitoringDyldMainEv: undefined,
    cookieAddr: undefined,

    stackloader: undefined,
    ldrx8: undefined,
    dispatch: undefined,
    movx4: undefined,
    regloader: undefined,

    resolve() {
        // iOS 12.5.7, iPhone 5s
        // Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Mobile/15E148 Safari/604.1
        if (navigator.userAgent.match(/OS 12_5(_\d+)?/) || navigator.userAgent.match(/OS 12_4(_\d+)?/) || navigator.userAgent.match(/OS 12_3(_\d+)?/) || navigator.userAgent.match(/OS 12_2(_\d+)?/)) {
            log("[i] offsets selected for iOS 12.2+");

            this.memPoolStart = 0xC8;
            this.memPoolEnd = 0xD0;
            this.cookieAddr = (0x8ECA0 + 0x38);
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
