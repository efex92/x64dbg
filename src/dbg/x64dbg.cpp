/**
 @file x64dbg.cpp

 @brief Implements the 64 debug class.
 */

#include "_global.h"
#include "command.h"
#include "variable.h"
#include "debugger.h"
#include "simplescript.h"
#include "console.h"
#include "x64dbg.h"
#include "msgqueue.h"
#include "threading.h"
#include "watch.h"
#include "plugin_loader.h"
#include "_dbgfunctions.h"
#include <capstone_wrapper.h>
#include "_scriptapi_gui.h"
#include "filehelper.h"
#include "database.h"
#include "mnemonichelp.h"
#include "datainst_helper.h"
#include "exception.h"
#include "expressionfunctions.h"
#include "yara/yara.h"

static MESSAGE_STACK* gMsgStack = 0;
static HANDLE hCommandLoopThread = 0;
static bool bStopCommandLoopThread = false;
static char alloctrace[MAX_PATH] = "";
static bool bIsStopped = true;
static char scriptDllDir[MAX_PATH] = "";
static String notesFile;

static bool cbStrLen(int argc, char* argv[])
{
    if(IsArgumentsLessThan(argc, 2))
        return false;
    dprintf_untranslated("\"%s\"[%d]\n", argv[1], int(strlen(argv[1])));
    return true;
}

static bool cbClearLog(int argc, char* argv[])
{
    GuiLogClear();
    return true;
}

static bool cbPrintf(int argc, char* argv[])
{
    if(argc < 2)
        dprintf("\n");
    else
        dprintf("%s", argv[1]);
    return true;
}

static bool DbgScriptDllExec(const char* dll);

static bool cbScriptDll(int argc, char* argv[])
{
    if(IsArgumentsLessThan(argc, 2))
        return false;
    return DbgScriptDllExec(argv[1]);
}

#include "cmd-all.h"

/**
\brief register the all the commands
*/
static void registercommands()
{
    cmdinit();

    //general purpose
    dbgcmdnew("inc", cbInstrInc, false, QT_TRANSLATE_NOOP("DBG", "Increament value"));
    dbgcmdnew("dec", cbInstrDec, false, QT_TRANSLATE_NOOP("DBG", "Decreament value"));
    dbgcmdnew("add", cbInstrAdd, false, QT_TRANSLATE_NOOP("DBG", "Add values"));
    dbgcmdnew("sub", cbInstrSub, false, QT_TRANSLATE_NOOP("DBG", "Subtract values"));
    dbgcmdnew("mul", cbInstrMul, false, QT_TRANSLATE_NOOP("DBG", "Multiply values"));
    dbgcmdnew("div", cbInstrDiv, false, QT_TRANSLATE_NOOP("DBG", "Divide values"));
    dbgcmdnew("and", cbInstrAnd, false, QT_TRANSLATE_NOOP("DBG", "Bitwise and"));
    dbgcmdnew("or", cbInstrOr, false, QT_TRANSLATE_NOOP("DBG", "Bitwise or"));
    dbgcmdnew("xor", cbInstrXor, false, QT_TRANSLATE_NOOP("DBG", "Bitwise xor"));
    dbgcmdnew("neg", cbInstrNeg, false, QT_TRANSLATE_NOOP("DBG", "Negate"));
    dbgcmdnew("not", cbInstrNot, false, QT_TRANSLATE_NOOP("DBG", "Bitwise not"));
    dbgcmdnew("bswap", cbInstrBswap, false, QT_TRANSLATE_NOOP("DBG", "Swap byte order"));
    dbgcmdnew("rol", cbInstrRol, false, QT_TRANSLATE_NOOP("DBG", "Rotate left"));
    dbgcmdnew("ror", cbInstrRor, false, QT_TRANSLATE_NOOP("DBG", "Rotate right"));
    dbgcmdnew("shl\1sal", cbInstrShl, false, QT_TRANSLATE_NOOP("DBG", "Shift left"));
    dbgcmdnew("shr", cbInstrShr, false, QT_TRANSLATE_NOOP("DBG", "Shift right"));
    dbgcmdnew("sar", cbInstrSar, false, QT_TRANSLATE_NOOP("DBG", "Arithmetic shift right"));
    dbgcmdnew("push", cbInstrPush, true, QT_TRANSLATE_NOOP("DBG", "Push a value on the stack"));
    dbgcmdnew("pop", cbInstrPop, true, QT_TRANSLATE_NOOP("DBG", "Pop a value from stack"));
    dbgcmdnew("test", cbInstrTest, false, QT_TRANSLATE_NOOP("DBG", "Test and set flags"));
    dbgcmdnew("cmp", cbInstrCmp, false, QT_TRANSLATE_NOOP("DBG", "Compare and set flags"));
    dbgcmdnew("mov\1set", cbInstrMov, false, QT_TRANSLATE_NOOP("DBG", "Move")); //mov a variable, arg1:dest,arg2:src

    //debug control
    dbgcmdnew("InitDebug\1init\1initdbg", cbDebugInit, false, QT_TRANSLATE_NOOP("DBG", "Start debugger")); //init debugger arg1:exefile,[arg2:commandline]
    dbgcmdnew("StopDebug\1stop\1dbgstop", cbDebugStop, true, QT_TRANSLATE_NOOP("DBG", "stop debugger")); //stop debugger
    dbgcmdnew("AttachDebugger\1attach", cbDebugAttach, false, QT_TRANSLATE_NOOP("DBG", "Attach to a process")); //attach
    dbgcmdnew("DetachDebugger\1detach", cbDebugDetach, true, QT_TRANSLATE_NOOP("DBG", "Detach from a process")); //detach
    dbgcmdnew("run\1go\1r\1g", cbDebugRun, true, QT_TRANSLATE_NOOP("DBG", "Run the debuggee")); //unlock WAITID_RUN
    dbgcmdnew("erun\1egun\1er\1eg", cbDebugErun, true, QT_TRANSLATE_NOOP("DBG", "run + skip second chance exceptions")); //run + skip first chance exceptions
    dbgcmdnew("serun\1sego", cbDebugSerun, true, QT_TRANSLATE_NOOP("DBG", "run + swallow exception")); //run + swallow exception
    dbgcmdnew("pause", cbDebugPause, false, QT_TRANSLATE_NOOP("DBG", "pause debugger")); //pause debugger
    dbgcmdnew("DebugContinue\1con", cbDebugContinue, true, QT_TRANSLATE_NOOP("DBG", "set continue status")); //set continue status
    dbgcmdnew("StepInto\1sti", cbDebugStepInto, true, QT_TRANSLATE_NOOP("DBG", "StepInto")); //StepInto
    dbgcmdnew("eStepInto\1esti", cbDebugeStepInto, true, QT_TRANSLATE_NOOP("DBG", "StepInto + skip second chance exceptions")); //StepInto + skip first chance exceptions
    dbgcmdnew("seStepInto\1sesti", cbDebugseStepInto, true, QT_TRANSLATE_NOOP("DBG", "StepInto + swallow exception")); //StepInto + swallow exception
    dbgcmdnew("StepOver\1step\1sto\1st", cbDebugStepOver, true, QT_TRANSLATE_NOOP("DBG", "StepOver")); //StepOver
    dbgcmdnew("eStepOver\1estep\1esto\1est", cbDebugeStepOver, true, QT_TRANSLATE_NOOP("DBG", "StepOver + skip second chance exceptions")); //StepOver + skip first chance exceptions
    dbgcmdnew("seStepOver\1sestep\1sesto\1sest", cbDebugseStepOver, true, QT_TRANSLATE_NOOP("DBG", "StepOver + swallow exception")); //StepOver + swallow exception
    dbgcmdnew("SingleStep\1sstep\1sst", cbDebugSingleStep, true, QT_TRANSLATE_NOOP("DBG", "Single Step n times")); //SingleStep arg1:count
    dbgcmdnew("eSingleStep\1esstep\1esst", cbDebugeSingleStep, true, QT_TRANSLATE_NOOP("DBG", "Single Step n times + skip second-chance exceptions")); //SingleStep arg1:count + skip first chance exceptions
    dbgcmdnew("StepOut\1rtr", cbDebugStepOut, true, QT_TRANSLATE_NOOP("DBG", "StepOut")); //StepOut
    dbgcmdnew("eStepOut\1ertr", cbDebugeStepOut, true, QT_TRANSLATE_NOOP("DBG", "rtr + skip second chance exceptions")); //rtr + skip first chance exceptions
    dbgcmdnew("skip", cbDebugSkip, true, QT_TRANSLATE_NOOP("DBG", "skip one instruction")); //skip one instruction
    dbgcmdnew("InstrUndo", cbInstrInstrUndo, true, QT_TRANSLATE_NOOP("DBG", "Instruction undo")); //Instruction undo

    //breakpoint control
    dbgcmdnew("SetBPX\1bp\1bpx", cbDebugSetBPX, true, QT_TRANSLATE_NOOP("DBG", "breakpoint")); //breakpoint
    dbgcmdnew("DeleteBPX\1bpc\1bc", cbDebugDeleteBPX, true, QT_TRANSLATE_NOOP("DBG", "breakpoint delete")); //breakpoint delete
    dbgcmdnew("EnableBPX\1bpe\1be", cbDebugEnableBPX, true, QT_TRANSLATE_NOOP("DBG", "breakpoint enable")); //breakpoint enable
    dbgcmdnew("DisableBPX\1bpd\1bd", cbDebugDisableBPX, true, QT_TRANSLATE_NOOP("DBG", "breakpoint disable")); //breakpoint disable
    dbgcmdnew("SetHardwareBreakpoint\1bph\1bphws", cbDebugSetHardwareBreakpoint, true, QT_TRANSLATE_NOOP("DBG", "hardware breakpoint")); //hardware breakpoint
    dbgcmdnew("DeleteHardwareBreakpoint\1bphc\1bphwc", cbDebugDeleteHardwareBreakpoint, true, QT_TRANSLATE_NOOP("DBG", "delete hardware breakpoint")); //delete hardware breakpoint
    dbgcmdnew("EnableHardwareBreakpoint\1bphe\1bphwe", cbDebugEnableHardwareBreakpoint, true, QT_TRANSLATE_NOOP("DBG", "enable hardware breakpoint")); //enable hardware breakpoint
    dbgcmdnew("DisableHardwareBreakpoint\1bphd\1bphwd", cbDebugDisableHardwareBreakpoint, true, QT_TRANSLATE_NOOP("DBG", "disable hardware breakpoint")); //disable hardware breakpoint
    dbgcmdnew("SetMemoryBPX\1membp\1bpm", cbDebugSetMemoryBpx, true, QT_TRANSLATE_NOOP("DBG", "SetMemoryBPX")); //SetMemoryBPX
    dbgcmdnew("DeleteMemoryBPX\1membpc\1bpmc", cbDebugDeleteMemoryBreakpoint, true, QT_TRANSLATE_NOOP("DBG", "delete memory breakpoint")); //delete memory breakpoint
    dbgcmdnew("EnableMemoryBreakpoint\1membpe\1bpme", cbDebugEnableMemoryBreakpoint, true, QT_TRANSLATE_NOOP("DBG", "enable memory breakpoint")); //enable memory breakpoint
    dbgcmdnew("DisableMemoryBreakpoint\1membpd\1bpmd", cbDebugDisableMemoryBreakpoint, true, QT_TRANSLATE_NOOP("DBG", "enable memory breakpoint")); //enable memory breakpoint
    dbgcmdnew("LibrarianSetBreakpoint\1bpdll", cbDebugBpDll, true, QT_TRANSLATE_NOOP("DBG", "set dll breakpoint")); //set dll breakpoint
    dbgcmdnew("LibrarianRemoveBreakpoint\1bcdll", cbDebugBcDll, true, QT_TRANSLATE_NOOP("DBG", "remove dll breakpoint")); //remove dll breakpoint
    dbgcmdnew("LibrarianEnableBreakpoint\1bpedll", cbDebugBpDllEnable, true, QT_TRANSLATE_NOOP("DBG", "enable dll breakpoint")); //enable dll breakpoint
    dbgcmdnew("LibrarianDisableBreakpoint\1bpddll", cbDebugBpDllDisable, true, QT_TRANSLATE_NOOP("DBG", "disable dll breakpoint")); //disable dll breakpoint
    dbgcmdnew("SetExceptionBPX", cbDebugSetExceptionBPX, true, QT_TRANSLATE_NOOP("DBG", "set exception breakpoint")); //set exception breakpoint
    dbgcmdnew("DeleteExceptionBPX", cbDebugDeleteExceptionBPX, true, QT_TRANSLATE_NOOP("DBG", "delete exception breakpoint")); //delete exception breakpoint
    dbgcmdnew("EnableExceptionBPX", cbDebugEnableExceptionBPX, true, QT_TRANSLATE_NOOP("DBG", "enable exception breakpoint")); //enable exception breakpoint
    dbgcmdnew("DisableExceptionBPX", cbDebugDisableExceptionBPX, true, QT_TRANSLATE_NOOP("DBG", "disable exception breakpoint")); //disable exception breakpoint
    dbgcmdnew("bpgoto", cbDebugSetBPGoto, true, QT_TRANSLATE_NOOP("DBG", "Set breakpoint to redirect the instruction pointer automatically"));
    dbgcmdnew("bplist", cbDebugBplist, true, QT_TRANSLATE_NOOP("DBG", "breakpoint list")); //breakpoint list
    dbgcmdnew("SetBPXOptions\1bptype", cbDebugSetBPXOptions, false, QT_TRANSLATE_NOOP("DBG", "breakpoint type")); //breakpoint type

    //conditional breakpoint control
    dbgcmdnew("SetBreakpointName\1bpname", cbDebugSetBPXName, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint name")); //set breakpoint name
    dbgcmdnew("SetBreakpointCondition\1bpcond\1bpcnd", cbDebugSetBPXCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint breakCondition")); //set breakpoint breakCondition
    dbgcmdnew("SetBreakpointLog\1bplog\1bpl", cbDebugSetBPXLog, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint logText")); //set breakpoint logText
    dbgcmdnew("SetBreakpointLogCondition\1bplogcondition", cbDebugSetBPXLogCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint logCondition")); //set breakpoint logCondition
    dbgcmdnew("SetBreakpointCommand", cbDebugSetBPXCommand, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint command on hit")); //set breakpoint command on hit
    dbgcmdnew("SetBreakpointCommandCondition", cbDebugSetBPXCommandCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint commandCondition")); //set breakpoint commandCondition
    dbgcmdnew("SetBreakpointFastResume", cbDebugSetBPXFastResume, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint fast resume")); //set breakpoint fast resume
    dbgcmdnew("SetBreakpointSingleshoot", cbDebugSetBPXSingleshoot, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint singleshoot")); //set breakpoint singleshoot
    dbgcmdnew("SetBreakpointSilent", cbDebugSetBPXSilent, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint fast resume")); //set breakpoint fast resume
    dbgcmdnew("GetBreakpointHitCount", cbDebugGetBPXHitCount, true, QT_TRANSLATE_NOOP("DBG", "get breakpoint hit count")); //get breakpoint hit count
    dbgcmdnew("ResetBreakpointHitCount", cbDebugResetBPXHitCount, true, QT_TRANSLATE_NOOP("DBG", "reset breakpoint hit count")); //reset breakpoint hit count

    dbgcmdnew("SetHardwareBreakpointName\1bphwname", cbDebugSetBPXHardwareName, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint name")); //set breakpoint name
    dbgcmdnew("SetHardwareBreakpointCondition\1bphwcond", cbDebugSetBPXHardwareCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint breakCondition")); //set breakpoint breakCondition
    dbgcmdnew("SetHardwareBreakpointLog\1bphwlog", cbDebugSetBPXHardwareLog, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint logText")); //set breakpoint logText
    dbgcmdnew("SetHardwareBreakpointLogCondition\1bphwlogcondition", cbDebugSetBPXHardwareLogCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint logText")); //set breakpoint logText
    dbgcmdnew("SetHardwareBreakpointCommand", cbDebugSetBPXHardwareCommand, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint command on hit")); //set breakpoint command on hit
    dbgcmdnew("SetHardwareBreakpointCommandCondition", cbDebugSetBPXHardwareCommandCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint commandCondition")); //set breakpoint commandCondition
    dbgcmdnew("SetHardwareBreakpointFastResume", cbDebugSetBPXHardwareFastResume, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint fast resume")); //set breakpoint fast resume
    dbgcmdnew("SetHardwareBreakpointSingleshoot", cbDebugSetBPXHardwareSingleshoot, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint singleshoot")); //set breakpoint singleshoot
    dbgcmdnew("SetHardwareBreakpointSilent", cbDebugSetBPXHardwareSilent, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint fast resume")); //set breakpoint fast resume
    dbgcmdnew("GetHardwareBreakpointHitCount", cbDebugGetBPXHardwareHitCount, true, QT_TRANSLATE_NOOP("DBG", "get breakpoint hit count")); //get breakpoint hit count
    dbgcmdnew("ResetHardwareBreakpointHitCount", cbDebugResetBPXHardwareHitCount, true, QT_TRANSLATE_NOOP("DBG", "reset breakpoint hit count")); //reset breakpoint hit count

    dbgcmdnew("SetMemoryBreakpointName\1bpmname", cbDebugSetBPXMemoryName, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint name")); //set breakpoint name
    dbgcmdnew("SetMemoryBreakpointCondition\1bpmcond", cbDebugSetBPXMemoryCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint breakCondition")); //set breakpoint breakCondition
    dbgcmdnew("SetMemoryBreakpointLog\1bpmlog", cbDebugSetBPXMemoryLog, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint log")); //set breakpoint log
    dbgcmdnew("SetMemoryBreakpointLogCondition\1bpmlogcondition", cbDebugSetBPXMemoryLogCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint logCondition")); //set breakpoint logCondition
    dbgcmdnew("SetMemoryBreakpointCommand", cbDebugSetBPXMemoryCommand, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint command on hit")); //set breakpoint command on hit
    dbgcmdnew("SetMemoryBreakpointCommandCondition", cbDebugSetBPXMemoryCommandCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint commandCondition")); //set breakpoint commandCondition
    dbgcmdnew("SetMemoryBreakpointFastResume", cbDebugSetBPXMemoryFastResume, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint fast resume")); //set breakpoint fast resume
    dbgcmdnew("SetMemoryBreakpointSingleshoot", cbDebugSetBPXMemorySingleshoot, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint singleshoot")); //set breakpoint singleshoot
    dbgcmdnew("SetMemoryBreakpointSilent", cbDebugSetBPXMemorySilent, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint fast resume")); //set breakpoint fast resume
    dbgcmdnew("GetMemoryBreakpointHitCount", cbDebugGetBPXMemoryHitCount, true, QT_TRANSLATE_NOOP("DBG", "get breakpoint hit count")); //get breakpoint hit count
    dbgcmdnew("ResetMemoryBreakpointHitCount", cbDebugResetBPXMemoryHitCount, true, QT_TRANSLATE_NOOP("DBG", "reset breakpoint hit count")); //reset breakpoint hit count

    dbgcmdnew("SetLibrarianBreakpointName", cbDebugSetBPXDLLName, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint name")); //set breakpoint name
    dbgcmdnew("SetLibrarianBreakpointCondition", cbDebugSetBPXDLLCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint breakCondition")); //set breakpoint breakCondition
    dbgcmdnew("SetLibrarianBreakpointLog", cbDebugSetBPXDLLLog, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint log")); //set breakpoint log
    dbgcmdnew("SetLibrarianBreakpointLogCondition", cbDebugSetBPXDLLLogCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint logCondition")); //set breakpoint logCondition
    dbgcmdnew("SetLibrarianBreakpointCommand", cbDebugSetBPXDLLCommand, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint command on hit")); //set breakpoint command on hit
    dbgcmdnew("SetLibrarianBreakpointCommandCondition", cbDebugSetBPXDLLCommandCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint commandCondition")); //set breakpoint commandCondition
    dbgcmdnew("SetLibrarianBreakpointFastResume", cbDebugSetBPXDLLFastResume, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint fast resume")); //set breakpoint fast resume
    dbgcmdnew("SetLibrarianBreakpointSingleshoot", cbDebugSetBPXDLLSingleshoot, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint singleshoot")); //set breakpoint singleshoot
    dbgcmdnew("SetLibrarianBreakpointSilent", cbDebugSetBPXDLLSilent, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint fast resume")); //set breakpoint fast resume
    dbgcmdnew("GetLibrarianBreakpointHitCount", cbDebugGetBPXDLLHitCount, true, QT_TRANSLATE_NOOP("DBG", "get breakpoint hit count")); //get breakpoint hit count
    dbgcmdnew("ResetLibrarianBreakpointHitCount", cbDebugResetBPXDLLHitCount, true, QT_TRANSLATE_NOOP("DBG", "reset breakpoint hit count")); //reset breakpoint hit count

    dbgcmdnew("SetExceptionBreakpointName", cbDebugSetBPXExceptionName, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint name")); //set breakpoint name
    dbgcmdnew("SetExceptionBreakpointCondition", cbDebugSetBPXExceptionCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint breakCondition")); //set breakpoint breakCondition
    dbgcmdnew("SetExceptionBreakpointLog", cbDebugSetBPXExceptionLog, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint log")); //set breakpoint log
    dbgcmdnew("SetExceptionBreakpointLogCondition", cbDebugSetBPXExceptionLogCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint logCondition")); //set breakpoint logCondition
    dbgcmdnew("SetExceptionBreakpointCommand", cbDebugSetBPXExceptionCommand, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint command on hit")); //set breakpoint command on hit
    dbgcmdnew("SetExceptionBreakpointCommandCondition", cbDebugSetBPXExceptionCommandCondition, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint commandCondition")); //set breakpoint commandCondition
    dbgcmdnew("SetExceptionBreakpointFastResume", cbDebugSetBPXExceptionFastResume, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint fast resume")); //set breakpoint fast resume
    dbgcmdnew("SetExceptionBreakpointSingleshoot", cbDebugSetBPXExceptionSingleshoot, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint singleshoot")); //set breakpoint singleshoot
    dbgcmdnew("SetExceptionBreakpointSilent", cbDebugSetBPXExceptionSilent, true, QT_TRANSLATE_NOOP("DBG", "set breakpoint fast resume")); //set breakpoint fast resume
    dbgcmdnew("GetExceptionBreakpointHitCount", cbDebugGetBPXExceptionHitCount, true, QT_TRANSLATE_NOOP("DBG", "get breakpoint hit count")); //get breakpoint hit count
    dbgcmdnew("ResetExceptionBreakpointHitCount", cbDebugResetBPXExceptionHitCount, true, QT_TRANSLATE_NOOP("DBG", "reset breakpoint hit count")); //reset breakpoint hit count

    //tracing
    dbgcmdnew("TraceIntoConditional\1ticnd", cbDebugTraceIntoConditional, true, QT_TRANSLATE_NOOP("DBG", "Trace into conditional")); //Trace into conditional
    dbgcmdnew("TraceOverConditional\1tocnd", cbDebugTraceOverConditional, true, QT_TRANSLATE_NOOP("DBG", "Trace over conditional")); //Trace over conditional
    dbgcmdnew("TraceIntoBeyondTraceRecord\1tibt", cbDebugTraceIntoBeyondTraceRecord, true, QT_TRANSLATE_NOOP("DBG", "Trace into beyond trace record")); //Trace into beyond trace record
    dbgcmdnew("TraceOverBeyondTraceRecord\1tobt", cbDebugTraceOverBeyondTraceRecord, true, QT_TRANSLATE_NOOP("DBG", "Trace over beyond trace record")); //Trace over beyond trace record
    dbgcmdnew("TraceIntoIntoTraceRecord\1tiit", cbDebugTraceIntoIntoTraceRecord, true, QT_TRANSLATE_NOOP("DBG", "Trace into into trace record")); //Trace into into trace record
    dbgcmdnew("TraceOverIntoTraceRecord\1toit", cbDebugTraceOverIntoTraceRecord, true, QT_TRANSLATE_NOOP("DBG", "Trace over into trace record")); //Trace over into trace record
    dbgcmdnew("RunToParty", cbDebugRunToParty, true, QT_TRANSLATE_NOOP("DBG", "Run to code in a party")); //Run to code in a party
    dbgcmdnew("RunToUserCode\1rtu", cbDebugRunToUserCode, true, QT_TRANSLATE_NOOP("DBG", "Run to user code")); //Run to user code
    dbgcmdnew("TraceSetLog\1SetTraceLog", cbDebugTraceSetLog, true, QT_TRANSLATE_NOOP("DBG", "Set trace log text + condition")); //Set trace log text + condition
    dbgcmdnew("TraceSetCommand\1SetTraceCommand", cbDebugTraceSetCommand, true, QT_TRANSLATE_NOOP("DBG", "Set trace command text + condition")); //Set trace command text + condition

    //thread control
    dbgcmdnew("createthread\1threadcreate\1newthread\1threadnew", cbDebugCreatethread, true, QT_TRANSLATE_NOOP("DBG", "create thread")); //create thread
    dbgcmdnew("switchthread\1threadswitch", cbDebugSwitchthread, true, QT_TRANSLATE_NOOP("DBG", "switch thread")); //switch thread
    dbgcmdnew("suspendthread\1threadsuspend", cbDebugSuspendthread, true, QT_TRANSLATE_NOOP("DBG", "suspend thread")); //suspend thread
    dbgcmdnew("resumethread\1threadresume", cbDebugResumethread, true, QT_TRANSLATE_NOOP("DBG", "resume thread")); //resume thread
    dbgcmdnew("killthread\1threadkill", cbDebugKillthread, true, QT_TRANSLATE_NOOP("DBG", "kill thread")); //kill thread
    dbgcmdnew("suspendallthreads\1threadsuspendall", cbDebugSuspendAllThreads, true, QT_TRANSLATE_NOOP("DBG", "suspend all threads")); //suspend all threads
    dbgcmdnew("resumeallthreads\1threadresumeall", cbDebugResumeAllThreads, true, QT_TRANSLATE_NOOP("DBG", "resume all threads")); //resume all threads
    dbgcmdnew("setthreadpriority\1setprioritythread\1threadsetpriority", cbDebugSetPriority, true, QT_TRANSLATE_NOOP("DBG", "set thread priority")); //set thread priority
    dbgcmdnew("threadsetname\1setthreadname", cbDebugSetthreadname, true, QT_TRANSLATE_NOOP("DBG", "set thread name")); //set thread name

    //memory operations
    dbgcmdnew("alloc", cbDebugAlloc, true, QT_TRANSLATE_NOOP("DBG", "allocate memory")); //allocate memory
    dbgcmdnew("free", cbDebugFree, true, QT_TRANSLATE_NOOP("DBG", "free memory")); //free memory
    dbgcmdnew("Fill\1memset", cbDebugMemset, true, QT_TRANSLATE_NOOP("DBG", "memset")); //memset
    dbgcmdnew("getpagerights\1getrightspage", cbDebugGetPageRights, true, QT_TRANSLATE_NOOP("DBG", "Get page access rights")); //Get page access rights
    dbgcmdnew("setpagerights\1setrightspage", cbDebugSetPageRights, true, QT_TRANSLATE_NOOP("DBG", "Set page access rights")); //Set page access rights
    dbgcmdnew("savedata", cbInstrSavedata, true, QT_TRANSLATE_NOOP("DBG", "save data to disk")); //save data to disk

    //operating system control
    dbgcmdnew("GetPrivilegeState", cbGetPrivilegeState, true, QT_TRANSLATE_NOOP("DBG", "Get privilege state")); //get priv state
    dbgcmdnew("EnablePrivilege", cbEnablePrivilege, true, QT_TRANSLATE_NOOP("DBG", "Enable privilege")); //enable priv
    dbgcmdnew("DisablePrivilege", cbDisablePrivilege, true, QT_TRANSLATE_NOOP("DBG", "Disable privilege")); //disable priv
    dbgcmdnew("handleclose\1closehandle", cbHandleClose, true, QT_TRANSLATE_NOOP("DBG", "Close remote handle")); //close remote handle

    //watch control
    dbgcmdnew("AddWatch", cbAddWatch, true, QT_TRANSLATE_NOOP("DBG", "add watch")); // add watch
    dbgcmdnew("DelWatch", cbDelWatch, true, QT_TRANSLATE_NOOP("DBG", "delete watch")); // delete watch
    dbgcmdnew("SetWatchdog", cbSetWatchdog, true, QT_TRANSLATE_NOOP("DBG", "Setup watchdog")); // Setup watchdog
    dbgcmdnew("SetWatchExpression", cbSetWatchExpression, true, QT_TRANSLATE_NOOP("DBG", "Set watch expression")); // Set watch expression
    dbgcmdnew("SetWatchName", cbSetWatchName, true, QT_TRANSLATE_NOOP("DBG", "Set watch name")); // Set watch name
    dbgcmdnew("CheckWatchdog", cbCheckWatchdog, true, QT_TRANSLATE_NOOP("DBG", "Set Watchdog")); // Set Watchdog

    //variables
    dbgcmdnew("varnew\1var", cbInstrVar, false, QT_TRANSLATE_NOOP("DBG", "make a variable")); //make a variable arg1:name,[arg2:value]
    dbgcmdnew("vardel", cbInstrVarDel, false, QT_TRANSLATE_NOOP("DBG", "delete a variable")); //delete a variable, arg1:variable name
    dbgcmdnew("varlist", cbInstrVarList, false, QT_TRANSLATE_NOOP("DBG", "list variables")); //list variables[arg1:type filter]

    //searching
    dbgcmdnew("find", cbInstrFind, true, QT_TRANSLATE_NOOP("DBG", "find a pattern")); //find a pattern
    dbgcmdnew("findall", cbInstrFindAll, true, QT_TRANSLATE_NOOP("DBG", "find all patterns")); //find all patterns
    dbgcmdnew("findallmem\1findmemall", cbInstrFindAllMem, true, QT_TRANSLATE_NOOP("DBG", "memory map pattern find")); //memory map pattern find
    dbgcmdnew("findasm\1asmfind", cbInstrFindAsm, true, QT_TRANSLATE_NOOP("DBG", "find instruction")); //find instruction
    dbgcmdnew("reffind\1findref\1ref", cbInstrRefFind, true, QT_TRANSLATE_NOOP("DBG", "find references to a value")); //find references to a value
    dbgcmdnew("reffindrange\1findrefrange\1refrange", cbInstrRefFindRange, true, QT_TRANSLATE_NOOP("DBG", "find references to the range"));
    dbgcmdnew("refstr\1strref", cbInstrRefStr, true, QT_TRANSLATE_NOOP("DBG", "find string references")); //find string references
    dbgcmdnew("modcallfind", cbInstrModCallFind, true, QT_TRANSLATE_NOOP("DBG", "find intermodular calls")); //find intermodular calls
    dbgcmdnew("yara", cbInstrYara, true, QT_TRANSLATE_NOOP("DBG", "yara test command")); //yara test command
    dbgcmdnew("yaramod", cbInstrYaramod, true, QT_TRANSLATE_NOOP("DBG", "yara rule on module")); //yara rule on module
    dbgcmdnew("setmaxfindresult\1findsetmaxresult", cbInstrSetMaxFindResult, false, QT_TRANSLATE_NOOP("DBG", "set the maximum number of occurences found")); //set the maximum number of occurences found
    dbgcmdnew("guidfind\1findguid", cbInstrGUIDFind, true, QT_TRANSLATE_NOOP("DBG", "find GUID references")); //find GUID references

    //user database
    dbgcmdnew("dbsave\1savedb", cbInstrDbsave, true, QT_TRANSLATE_NOOP("DBG", "save program database")); //save program database
    dbgcmdnew("dbload\1loaddb", cbInstrDbload, true, QT_TRANSLATE_NOOP("DBG", "load program database")); //load program database
    dbgcmdnew("dbclear\1cleardb", cbInstrDbclear, true, QT_TRANSLATE_NOOP("DBG", "clear program database")); //clear program database

    dbgcmdnew("commentset\1cmt\1cmtset", cbInstrCommentSet, true, QT_TRANSLATE_NOOP("DBG", "set")); //set/edit comment
    dbgcmdnew("commentdel\1cmtc\1cmtdel", cbInstrCommentDel, true, QT_TRANSLATE_NOOP("DBG", "delete comment")); //delete comment
    dbgcmdnew("commentlist", cbInstrCommentList, true, QT_TRANSLATE_NOOP("DBG", "list comments")); //list comments
    dbgcmdnew("commentclear", cbInstrCommentClear, true, QT_TRANSLATE_NOOP("DBG", "clear comments")); //clear comments

    dbgcmdnew("labelset\1lbl\1lblset", cbInstrLabelSet, true, QT_TRANSLATE_NOOP("DBG", "set")); //set/edit label
    dbgcmdnew("labeldel\1lblc\1lbldel", cbInstrLabelDel, true, QT_TRANSLATE_NOOP("DBG", "delete label")); //delete label
    dbgcmdnew("labellist", cbInstrLabelList, true, QT_TRANSLATE_NOOP("DBG", "list labels")); //list labels
    dbgcmdnew("labelclear", cbInstrLabelClear, true, QT_TRANSLATE_NOOP("DBG", "clear labels")); //clear labels

    dbgcmdnew("bookmarkset\1bookmark", cbInstrBookmarkSet, true, QT_TRANSLATE_NOOP("DBG", "set bookmark")); //set bookmark
    dbgcmdnew("bookmarkdel\1bookmarkc", cbInstrBookmarkDel, true, QT_TRANSLATE_NOOP("DBG", "delete bookmark")); //delete bookmark
    dbgcmdnew("bookmarklist", cbInstrBookmarkList, true, QT_TRANSLATE_NOOP("DBG", "list bookmarks")); //list bookmarks
    dbgcmdnew("bookmarkclear", cbInstrBookmarkClear, true, QT_TRANSLATE_NOOP("DBG", "clear bookmarks")); //clear bookmarks

    dbgcmdnew("functionadd\1func", cbInstrFunctionAdd, true, QT_TRANSLATE_NOOP("DBG", "function")); //function
    dbgcmdnew("functiondel\1funcc", cbInstrFunctionDel, true, QT_TRANSLATE_NOOP("DBG", "function")); //function
    dbgcmdnew("functionlist", cbInstrFunctionList, true, QT_TRANSLATE_NOOP("DBG", "list functions")); //list functions
    dbgcmdnew("functionclear", cbInstrFunctionClear, false, QT_TRANSLATE_NOOP("DBG", "delete all functions")); //delete all functions

    dbgcmdnew("argumentadd", cbInstrArgumentAdd, true, QT_TRANSLATE_NOOP("DBG", "add argument")); //add argument
    dbgcmdnew("argumentdel", cbInstrArgumentDel, true, QT_TRANSLATE_NOOP("DBG", "delete argument")); //delete argument
    dbgcmdnew("argumentlist", cbInstrArgumentList, true, QT_TRANSLATE_NOOP("DBG", "list arguments")); //list arguments
    dbgcmdnew("argumentclear", cbInstrArgumentClear, false, QT_TRANSLATE_NOOP("DBG", "delete all arguments")); //delete all arguments

    //analysis
    dbgcmdnew("analyse\1analyze\1anal", cbInstrAnalyse, true, QT_TRANSLATE_NOOP("DBG", "Analyze the code")); //secret analysis command
    dbgcmdnew("exanal\1exanalyse\1exanalyze", cbInstrExanalyse, true, QT_TRANSLATE_NOOP("DBG", "exception directory analysis")); //exception directory analysis
    dbgcmdnew("cfanal\1cfanalyse\1cfanalyze", cbInstrCfanalyse, true, QT_TRANSLATE_NOOP("DBG", "control flow analysis")); //control flow analysis
    dbgcmdnew("analyse_nukem\1analyze_nukem\1anal_nukem", cbInstrAnalyseNukem, true, QT_TRANSLATE_NOOP("DBG", "Analyze the code with nukem's algorithm")); //secret analysis command #2
    dbgcmdnew("analxrefs\1analx", cbInstrAnalxrefs, true, QT_TRANSLATE_NOOP("DBG", "analyze xrefs")); //analyze xrefs
    dbgcmdnew("analrecur\1analr", cbInstrAnalrecur, true, QT_TRANSLATE_NOOP("DBG", "analyze a single function")); //analyze a single function
    dbgcmdnew("analadv", cbInstrAnalyseadv, true, QT_TRANSLATE_NOOP("DBG", "analyze xref")); //analyze xref,function and data
    dbgcmdnew("traceexecute", cbInstrTraceexecute, true, QT_TRANSLATE_NOOP("DBG", "execute trace record on address")); //execute trace record on address TODO: undocumented

    dbgcmdnew("virtualmod", cbInstrVirtualmod, true, QT_TRANSLATE_NOOP("DBG", "virtual module")); //virtual module
    dbgcmdnew("symdownload\1downloadsym", cbDebugDownloadSymbol, true, QT_TRANSLATE_NOOP("DBG", "download symbols")); //download symbols
    dbgcmdnew("imageinfo\1modimageinfo", cbInstrImageinfo, true, QT_TRANSLATE_NOOP("DBG", "print module image information")); //print module image information
    dbgcmdnew("GetRelocSize\1grs", cbInstrGetRelocSize, true, QT_TRANSLATE_NOOP("DBG", "get relocation table size")); //get relocation table size
    dbgcmdnew("exhandlers", cbInstrExhandlers, true, QT_TRANSLATE_NOOP("DBG", "enumerate exception handlers")); //enumerate exception handlers
    dbgcmdnew("exinfo", cbInstrExinfo, true, QT_TRANSLATE_NOOP("DBG", "dump last exception information")); //dump last exception information

    //types
    dbgcmdnew("DataUnknown", cbInstrDataUnknown, true, QT_TRANSLATE_NOOP("DBG", "mark as Unknown")); //mark as Unknown
    dbgcmdnew("DataByte\1db", cbInstrDataByte, true, QT_TRANSLATE_NOOP("DBG", "mark as Byte")); //mark as Byte
    dbgcmdnew("DataWord\1dw", cbInstrDataWord, true, QT_TRANSLATE_NOOP("DBG", "mark as Word")); //mark as Word
    dbgcmdnew("DataDword\1dd", cbInstrDataDword, true, QT_TRANSLATE_NOOP("DBG", "mark as Dword")); //mark as Dword
    dbgcmdnew("DataFword", cbInstrDataFword, true, QT_TRANSLATE_NOOP("DBG", "mark as Fword")); //mark as Fword
    dbgcmdnew("DataQword\1dq", cbInstrDataQword, true, QT_TRANSLATE_NOOP("DBG", "mark as Qword")); //mark as Qword
    dbgcmdnew("DataTbyte", cbInstrDataTbyte, true, QT_TRANSLATE_NOOP("DBG", "mark as Tbyte")); //mark as Tbyte
    dbgcmdnew("DataOword", cbInstrDataOword, true, QT_TRANSLATE_NOOP("DBG", "mark as Oword")); //mark as Oword
    dbgcmdnew("DataMmword", cbInstrDataMmword, true, QT_TRANSLATE_NOOP("DBG", "mark as Mmword")); //mark as Mmword
    dbgcmdnew("DataXmmword", cbInstrDataXmmword, true, QT_TRANSLATE_NOOP("DBG", "mark as Xmmword")); //mark as Xmmword
    dbgcmdnew("DataYmmword", cbInstrDataYmmword, true, QT_TRANSLATE_NOOP("DBG", "mark as Ymmword")); //mark as Ymmword
    dbgcmdnew("DataFloat\1DataReal4\1df", cbInstrDataFloat, true, QT_TRANSLATE_NOOP("DBG", "mark as Float")); //mark as Float
    dbgcmdnew("DataDouble\1DataReal8", cbInstrDataDouble, true, QT_TRANSLATE_NOOP("DBG", "mark as Double")); //mark as Double
    dbgcmdnew("DataLongdouble\1DataReal10", cbInstrDataLongdouble, true, QT_TRANSLATE_NOOP("DBG", "mark as Longdouble")); //mark as Longdouble
    dbgcmdnew("DataAscii\1da", cbInstrDataAscii, true, QT_TRANSLATE_NOOP("DBG", "mark as Ascii")); //mark as Ascii
    dbgcmdnew("DataUnicode\1du", cbInstrDataUnicode, true, QT_TRANSLATE_NOOP("DBG", "mark as Unicode")); //mark as Unicode
    dbgcmdnew("DataCode\1dc", cbInstrDataCode, true, QT_TRANSLATE_NOOP("DBG", "mark as Code")); //mark as Code
    dbgcmdnew("DataJunk", cbInstrDataJunk, true, QT_TRANSLATE_NOOP("DBG", "mark as Junk")); //mark as Junk
    dbgcmdnew("DataMiddle", cbInstrDataMiddle, true, QT_TRANSLATE_NOOP("DBG", "mark as Middle")); //mark as Middle

    dbgcmdnew("AddType", cbInstrAddType, false, ""); //AddType
    dbgcmdnew("AddStruct", cbInstrAddStruct, false, ""); //AddStruct
    dbgcmdnew("AddUnion", cbInstrAddUnion, false, ""); //AddUnion
    dbgcmdnew("AddMember", cbInstrAddMember, false, ""); //AddMember
    dbgcmdnew("AppendMember", cbInstrAppendMember, false, ""); //AppendMember
    dbgcmdnew("AddFunction", cbInstrAddFunction, false, ""); //AddFunction
    dbgcmdnew("AddArg", cbInstrAddArg, false, ""); //AddArg
    dbgcmdnew("AppendArg", cbInstrAppendArg, false, ""); //AppendArg
    dbgcmdnew("SizeofType", cbInstrSizeofType, false, ""); //SizeofType
    dbgcmdnew("VisitType", cbInstrVisitType, false, ""); //VisitType
    dbgcmdnew("ClearTypes", cbInstrClearTypes, false, ""); //ClearTypes
    dbgcmdnew("RemoveType", cbInstrRemoveType, false, ""); //RemoveType
    dbgcmdnew("EnumTypes", cbInstrEnumTypes, false, ""); //EnumTypes

    //plugins
    dbgcmdnew("StartScylla\1scylla\1imprec", cbDebugStartScylla, false, QT_TRANSLATE_NOOP("DBG", "start scylla")); //start scylla
    dbgcmdnew("plugload\1pluginload\1loadplugin", cbInstrPluginLoad, false, QT_TRANSLATE_NOOP("DBG", "load plugin")); //load plugin
    dbgcmdnew("plugunload\1pluginunload\1unloadplugin", cbInstrPluginUnload, false, QT_TRANSLATE_NOOP("DBG", "unload plugin")); //unload plugin

    //script
    dbgcmdnew("scriptload", cbScriptLoad, false, QT_TRANSLATE_NOOP("DBG", "load script file")); //load script file
    dbgcmdnew("msg", cbScriptMsg, false, QT_TRANSLATE_NOOP("DBG", "message box")); //message box
    dbgcmdnew("msgyn", cbScriptMsgyn, false, QT_TRANSLATE_NOOP("DBG", "message box with yes and no buttons")); //message box with yes and no buttons
    dbgcmdnew("log", cbInstrLog, false, QT_TRANSLATE_NOOP("DBG", "Add text to log")); //log command with superawesome hax
    dbgcmdnew("scriptdll\1dllscript", cbScriptDll, false, QT_TRANSLATE_NOOP("DBG", "execute a script DLL")); //execute a script DLL

    //gui
    dbgcmdnew("disasm\1dis\1d", cbDebugDisasm, true, QT_TRANSLATE_NOOP("DBG", "doDisasm")); //doDisasm
    dbgcmdnew("dump", cbDebugDump, true, QT_TRANSLATE_NOOP("DBG", "dump at address")); //dump at address
    dbgcmdnew("sdump", cbDebugStackDump, true, QT_TRANSLATE_NOOP("DBG", "dump at stack address")); //dump at stack address
    dbgcmdnew("memmapdump", cbDebugMemmapdump, true, QT_TRANSLATE_NOOP("DBG", "dump at memory map")); //dump at memory map
    dbgcmdnew("graph", cbInstrGraph, true, QT_TRANSLATE_NOOP("DBG", "graph function")); //graph function
    dbgcmdnew("guiupdateenable", cbInstrEnableGuiUpdate, true, QT_TRANSLATE_NOOP("DBG", "enable gui message")); //enable gui message
    dbgcmdnew("guiupdatedisable", cbInstrDisableGuiUpdate, true, QT_TRANSLATE_NOOP("DBG", "disable gui message")); //disable gui message
    dbgcmdnew("setfreezestack", cbDebugSetfreezestack, false, QT_TRANSLATE_NOOP("DBG", "freeze the stack from auto updates")); //freeze the stack from auto updates
    dbgcmdnew("refinit", cbInstrRefinit, false, QT_TRANSLATE_NOOP("DBG", "init a new references view")); //init a new references view
    dbgcmdnew("refadd", cbInstrRefadd, false, QT_TRANSLATE_NOOP("DBG", " add a line to a reference view")); // add a line to a reference view
    dbgcmdnew("EnableLog\1LogEnable", cbInstrEnableLog, false, QT_TRANSLATE_NOOP("DBG", "enable log")); //enable log
    dbgcmdnew("DisableLog\1LogDisable", cbInstrDisableLog, false, QT_TRANSLATE_NOOP("DBG", "disable log")); //disable log
    dbgcmdnew("ClearLog\1cls\1lc\1lclr", cbClearLog, false, QT_TRANSLATE_NOOP("DBG", "clear the log")); //clear the log
    dbgcmdnew("AddFavouriteTool", cbInstrAddFavTool, false, QT_TRANSLATE_NOOP("DBG", "add favourite tool")); //add favourite tool
    dbgcmdnew("AddFavouriteCommand", cbInstrAddFavCmd, false, QT_TRANSLATE_NOOP("DBG", "add favourite command")); //add favourite command
    dbgcmdnew("AddFavouriteToolShortcut\1SetFavouriteToolShortcut", cbInstrSetFavToolShortcut, false, QT_TRANSLATE_NOOP("DBG", "set favourite tool shortcut")); //set favourite tool shortcut
    dbgcmdnew("FoldDisassembly", cbInstrFoldDisassembly, true, QT_TRANSLATE_NOOP("DBG", "fold disassembly segment")); //fold disassembly segment

    //misc
    dbgcmdnew("chd", cbInstrChd, false, QT_TRANSLATE_NOOP("DBG", "Change directory")); //Change directory
    dbgcmdnew("zzz\1doSleep", cbInstrZzz, false, QT_TRANSLATE_NOOP("DBG", "sleep")); //sleep

    dbgcmdnew("HideDebugger\1dbh\1hide", cbDebugHide, true, QT_TRANSLATE_NOOP("DBG", "HideDebugger")); //HideDebugger
    dbgcmdnew("loadlib", cbDebugLoadLib, true, QT_TRANSLATE_NOOP("DBG", "Load DLL")); //Load DLL
    dbgcmdnew("asm", cbInstrAssemble, true, QT_TRANSLATE_NOOP("DBG", "assemble instruction")); //assemble instruction
    dbgcmdnew("gpa", cbInstrGpa, true, QT_TRANSLATE_NOOP("DBG", "get proc address")); //get proc address

    dbgcmdnew("setjit\1jitset", cbDebugSetJIT, false, QT_TRANSLATE_NOOP("DBG", "set JIT")); //set JIT
    dbgcmdnew("getjit\1jitget", cbDebugGetJIT, false, QT_TRANSLATE_NOOP("DBG", "get JIT")); //get JIT
    dbgcmdnew("getjitauto\1jitgetauto", cbDebugGetJITAuto, false, QT_TRANSLATE_NOOP("DBG", "get JIT Auto")); //get JIT Auto
    dbgcmdnew("setjitauto\1jitsetauto", cbDebugSetJITAuto, false, QT_TRANSLATE_NOOP("DBG", "set JIT Auto")); //set JIT Auto

    dbgcmdnew("getcommandline\1getcmdline", cbDebugGetCmdline, true, QT_TRANSLATE_NOOP("DBG", "Get CmdLine")); //Get CmdLine
    dbgcmdnew("setcommandline\1setcmdline", cbDebugSetCmdline, true, QT_TRANSLATE_NOOP("DBG", "Set CmdLine")); //Set CmdLine

    dbgcmdnew("mnemonichelp", cbInstrMnemonichelp, false, QT_TRANSLATE_NOOP("DBG", "mnemonic help")); //mnemonic help
    dbgcmdnew("mnemonicbrief", cbInstrMnemonicbrief, false, QT_TRANSLATE_NOOP("DBG", "mnemonic brief")); //mnemonic brief

    //undocumented
    dbgcmdnew("bench", cbDebugBenchmark, true, ""); //benchmark test (readmem etc)
    dbgcmdnew("dprintf", cbPrintf, false, ""); //printf
    dbgcmdnew("setstr\1strset", cbInstrSetstr, false, ""); //set a string variable
    dbgcmdnew("getstr\1strget", cbInstrGetstr, false, ""); //get a string variable
    dbgcmdnew("copystr\1strcpy", cbInstrCopystr, true, ""); //write a string variable to memory
    dbgcmdnew("looplist", cbInstrLoopList, true, ""); //list loops
    dbgcmdnew("capstone", cbInstrCapstone, true, ""); //disassemble using capstone
    dbgcmdnew("visualize", cbInstrVisualize, true, ""); //visualize analysis
    dbgcmdnew("meminfo", cbInstrMeminfo, true, ""); //command to debug memory map bugs
    dbgcmdnew("briefcheck", cbInstrBriefcheck, true, ""); //check if mnemonic briefs are missing
    dbgcmdnew("focusinfo", cbInstrFocusinfo, false, "");
    dbgcmdnew("printstack\1logstack", cbInstrPrintStack, true, QT_TRANSLATE_NOOP("DBG", "Print the call stack")); //print the call stack
};

bool cbCommandProvider(char* cmd, int maxlen)
{
    MESSAGE msg;
    MsgWait(gMsgStack, &msg);
    if(bStopCommandLoopThread)
        return false;
    char* newcmd = (char*)msg.param1;
    if(strlen(newcmd) >= deflen)
    {
        dprintf(QT_TRANSLATE_NOOP("DBG", "command cut at ~%d characters\n"), deflen);
        newcmd[deflen - 2] = 0;
    }
    strcpy_s(cmd, deflen, newcmd);
    efree(newcmd, "cbCommandProvider:newcmd"); //free allocated command
    return true;
}

/**
\brief Execute command asynchronized.
*/
extern "C" DLL_EXPORT bool _dbg_dbgcmdexec(const char* cmd)
{
    int len = (int)strlen(cmd);
    char* newcmd = (char*)emalloc((len + 1) * sizeof(char), "_dbg_dbgcmdexec:newcmd");
    strcpy_s(newcmd, len + 1, cmd);
    return MsgSend(gMsgStack, 0, (duint)newcmd, 0);
}

static DWORD WINAPI DbgCommandLoopThread(void* a)
{
    cmdloop();
    return 0;
}

typedef void(*SCRIPTDLLSTART)();

struct DLLSCRIPTEXECTHREADINFO
{
    DLLSCRIPTEXECTHREADINFO(HINSTANCE hScriptDll, SCRIPTDLLSTART AsyncStart)
        : hScriptDll(hScriptDll),
          AsyncStart(AsyncStart)
    {
    }

    HINSTANCE hScriptDll;
    SCRIPTDLLSTART AsyncStart;
};

static DWORD WINAPI DbgScriptDllExecThread(void* a)
{
    auto info = (DLLSCRIPTEXECTHREADINFO*)a;
    auto AsyncStart = info->AsyncStart;
    auto hScriptDll = info->hScriptDll;
    delete info;

    dputs(QT_TRANSLATE_NOOP("DBG", "[Script DLL] Calling export \"AsyncStart\"...\n"));
    AsyncStart();
    dputs(QT_TRANSLATE_NOOP("DBG", "[Script DLL] \"AsyncStart\" returned!\n"));

    dputs(QT_TRANSLATE_NOOP("DBG", "[Script DLL] Calling FreeLibrary..."));
    if(FreeLibrary(hScriptDll))
        dputs(QT_TRANSLATE_NOOP("DBG", "success!\n"));
    else
        dprintf(QT_TRANSLATE_NOOP("DBG", "failure (%08X)...\n"), GetLastError());

    return 0;
}

static bool DbgScriptDllExec(const char* dll)
{
    String dllPath = dll;
    if(dllPath.find('\\') == String::npos)
        dllPath = String(scriptDllDir) + String(dll);

    dprintf(QT_TRANSLATE_NOOP("DBG", "[Script DLL] Loading Script DLL \"%s\"...\n"), dllPath.c_str());

    auto hScriptDll = LoadLibraryW(StringUtils::Utf8ToUtf16(dllPath).c_str());
    if(hScriptDll)
    {
        dprintf(QT_TRANSLATE_NOOP("DBG", "[Script DLL] DLL loaded on 0x%p!\n"), hScriptDll);

        auto AsyncStart = SCRIPTDLLSTART(GetProcAddress(hScriptDll, "AsyncStart"));
        if(AsyncStart)
        {
            dputs(QT_TRANSLATE_NOOP("DBG", "[Script DLL] Creating thread to call the export \"AsyncStart\"...\n"));
            CloseHandle(CreateThread(nullptr, 0, DbgScriptDllExecThread, new DLLSCRIPTEXECTHREADINFO(hScriptDll, AsyncStart), 0, nullptr)); //on-purpose memory leak here
        }
        else
        {
            auto Start = SCRIPTDLLSTART(GetProcAddress(hScriptDll, "Start"));
            if(Start)
            {
                dputs(QT_TRANSLATE_NOOP("DBG", "[Script DLL] Calling export \"Start\"...\n"));
                Start();
                dputs(QT_TRANSLATE_NOOP("DBG", "[Script DLL] \"Start\" returned!\n"));
            }
            else
                dprintf(QT_TRANSLATE_NOOP("DBG", "[Script DLL] Failed to find the exports \"AsyncStart\" or \"Start\" (%s)!\n"), ErrorCodeToName(GetLastError()).c_str());

            dprintf(QT_TRANSLATE_NOOP("DBG", "[Script DLL] Calling FreeLibrary..."));
            if(FreeLibrary(hScriptDll))
                dputs(QT_TRANSLATE_NOOP("DBG", "success!\n"));
            else
                dprintf(QT_TRANSLATE_NOOP("DBG", "failure (%s)...\n"), ErrorCodeToName(GetLastError()).c_str());
        }
    }
    else
        dprintf(QT_TRANSLATE_NOOP("DBG", "[Script DLL] LoadLibary failed (%s)!\n"), ErrorCodeToName(GetLastError()).c_str());

    return true;
}

static DWORD WINAPI loadDbThread(LPVOID)
{
    // Load mnemonic help database
    String mnemonicHelpData;
    if(FileHelper::ReadAllText(StringUtils::sprintf("%s\\..\\mnemdb.json", szProgramDir), mnemonicHelpData))
    {
        if(MnemonicHelp::loadFromText(mnemonicHelpData.c_str()))
            dputs(QT_TRANSLATE_NOOP("DBG", "Mnemonic help database loaded!"));
        else
            dputs(QT_TRANSLATE_NOOP("DBG", "Failed to load mnemonic help database..."));
    }
    else
        dputs(QT_TRANSLATE_NOOP("DBG", "Failed to read mnemonic help database..."));

    // Load error codes
    if(ErrorCodeInit(StringUtils::sprintf("%s\\..\\errordb.txt", szProgramDir)))
        dputs(QT_TRANSLATE_NOOP("DBG", "Error codes database loaded!"));
    else
        dputs(QT_TRANSLATE_NOOP("DBG", "Failed to load error codes..."));

    // Load exception codes
    if(ExceptionCodeInit(StringUtils::sprintf("%s\\..\\exceptiondb.txt", szProgramDir)))
        dputs(QT_TRANSLATE_NOOP("DBG", "Exception codes database loaded!"));
    else
        dputs(QT_TRANSLATE_NOOP("DBG", "Failed to load exception codes..."));

    // Load NTSTATUS codes
    if(NtStatusCodeInit(StringUtils::sprintf("%s\\..\\ntstatusdb.txt", szProgramDir)))
        dputs(QT_TRANSLATE_NOOP("DBG", "NTSTATUS codes database loaded!"));
    else
        dputs(QT_TRANSLATE_NOOP("DBG", "Failed to load NTSTATUS codes..."));

    // Load global notes
    dputs(QT_TRANSLATE_NOOP("DBG", "Reading notes file..."));
    notesFile = String(szProgramDir) + "\\notes.txt";
    String text;
    if(FileHelper::ReadAllText(notesFile, text))
        GuiSetGlobalNotes(text.c_str());
    else
        dputs(QT_TRANSLATE_NOOP("DBG", "Reading notes failed..."));

    dputs(QT_TRANSLATE_NOOP("DBG", "File read thread finished!"));

    return 0;
}

extern "C" DLL_EXPORT const char* _dbg_dbginit()
{
    if(!EngineCheckStructAlignment(UE_STRUCT_TITAN_ENGINE_CONTEXT, sizeof(TITAN_ENGINE_CONTEXT_t)))
        return "Invalid TITAN_ENGINE_CONTEXT_t alignment!";

    static_assert(sizeof(TITAN_ENGINE_CONTEXT_t) == sizeof(REGISTERCONTEXT), "Invalid REGISTERCONTEXT alignment!");

    wchar_t wszDir[deflen] = L"";
    if(!GetModuleFileNameW(hInst, wszDir, deflen))
        return "GetModuleFileNameW failed!";
    strcpy_s(szProgramDir, StringUtils::Utf16ToUtf8(wszDir).c_str());
    int len = (int)strlen(szProgramDir);
    while(szProgramDir[len] != '\\')
        len--;
    szProgramDir[len] = 0;
#ifdef ENABLE_MEM_TRACE
    strcpy_s(alloctrace, szProgramDir);
    strcat_s(alloctrace, "\\alloctrace.txt");
    DeleteFileW(StringUtils::Utf8ToUtf16(alloctrace).c_str());
    setalloctrace(alloctrace);
#endif //ENABLE_MEM_TRACE

    dputs(QT_TRANSLATE_NOOP("DBG", "Initializing wait objects..."));
    waitinitialize();
    dputs(QT_TRANSLATE_NOOP("DBG", "Initializing debugger..."));
    dbginit();
    dputs(QT_TRANSLATE_NOOP("DBG", "Initializing debugger functions..."));
    dbgfunctionsinit();
    //#ifdef ENABLE_MEM_TRACE
    dputs(QT_TRANSLATE_NOOP("DBG", "Setting JSON memory management functions..."));
    json_set_alloc_funcs(json_malloc, json_free);
    //#endif //ENABLE_MEM_TRACE
    dputs(QT_TRANSLATE_NOOP("DBG", "Initializing capstone..."));
    Capstone::GlobalInitialize();
    dputs(QT_TRANSLATE_NOOP("DBG", "Initializing Yara..."));
    if(yr_initialize() != ERROR_SUCCESS)
        return "Failed to initialize Yara!";
    dputs(QT_TRANSLATE_NOOP("DBG", "Getting directory information..."));

    strcpy_s(scriptDllDir, szProgramDir);
    strcat_s(scriptDllDir, "\\scripts\\");
    initDataInstMap();

    dputs(QT_TRANSLATE_NOOP("DBG", "Start file read thread..."));
    CloseHandle(CreateThread(nullptr, 0, loadDbThread, nullptr, 0, nullptr));

    // Create database directory in the local debugger folder
    DbSetPath(StringUtils::sprintf("%s\\db", szProgramDir).c_str(), nullptr);

    char szLocalSymbolPath[MAX_PATH] = "";
    strcpy_s(szLocalSymbolPath, szProgramDir);
    strcat_s(szLocalSymbolPath, "\\symbols");

    Memory<char*> cachePath(MAX_SETTING_SIZE + 1);
    if(!BridgeSettingGet("Symbols", "CachePath", cachePath()) || !*cachePath())
    {
        strcpy_s(szSymbolCachePath, szLocalSymbolPath);
        BridgeSettingSet("Symbols", "CachePath", ".\\symbols");
    }
    else
    {
        if(_strnicmp(cachePath(), ".\\", 2) == 0)
        {
            strncpy_s(szSymbolCachePath, szProgramDir, _TRUNCATE);
            strncat_s(szSymbolCachePath, cachePath() + 1, _TRUNCATE);
        }
        else
        {
            // Trim the buffer to fit inside MAX_PATH
            strncpy_s(szSymbolCachePath, cachePath(), _TRUNCATE);
        }

        if(strstr(szSymbolCachePath, "http://") || strstr(szSymbolCachePath, "https://"))
        {
            if(Script::Gui::MessageYesNo(GuiTranslateText(QT_TRANSLATE_NOOP("DBG", "It is strongly discouraged to use symbol servers in your path directly (use the store option instead).\n\nDo you want me to fix this?"))))
            {
                strcpy_s(szSymbolCachePath, szLocalSymbolPath);
                BridgeSettingSet("Symbols", "CachePath", ".\\symbols");
            }
        }
    }
    dprintf(QT_TRANSLATE_NOOP("DBG", "Symbol Path: %s\n"), szSymbolCachePath);
    SetCurrentDirectoryW(StringUtils::Utf8ToUtf16(szProgramDir).c_str());
    dputs(QT_TRANSLATE_NOOP("DBG", "Allocating message stack..."));
    gMsgStack = MsgAllocStack();
    if(!gMsgStack)
        return "Could not allocate message stack!";
    dputs(QT_TRANSLATE_NOOP("DBG", "Initializing global script variables..."));
    varinit();
    dputs(QT_TRANSLATE_NOOP("DBG", "Registering debugger commands..."));
    registercommands();
    dputs(QT_TRANSLATE_NOOP("DBG", "Registering GUI command handler..."));
    ExpressionFunctions::Init();
    dputs(QT_TRANSLATE_NOOP("DBG", "Registering expression functions..."));
    SCRIPTTYPEINFO info;
    strcpy_s(info.name, GuiTranslateText(QT_TRANSLATE_NOOP("DBG", "Default")));
    info.id = 0;
    info.execute = DbgCmdExec;
    info.completeCommand = nullptr;
    GuiRegisterScriptLanguage(&info);
    dputs(QT_TRANSLATE_NOOP("DBG", "Registering Script DLL command handler..."));
    strcpy_s(info.name, GuiTranslateText(QT_TRANSLATE_NOOP("DBG", "Script DLL")));
    info.execute = DbgScriptDllExec;
    GuiRegisterScriptLanguage(&info);
    dputs(QT_TRANSLATE_NOOP("DBG", "Starting command loop..."));
    hCommandLoopThread = CreateThread(nullptr, 0, DbgCommandLoopThread, nullptr, 0, nullptr);
    char plugindir[deflen] = "";
    strcpy_s(plugindir, szProgramDir);
    strcat_s(plugindir, "\\plugins");
    CreateDirectoryW(StringUtils::Utf8ToUtf16(plugindir).c_str(), nullptr);
    CreateDirectoryW(StringUtils::Utf8ToUtf16(StringUtils::sprintf("%s\\memdumps", szProgramDir)).c_str(), nullptr);
    dputs(QT_TRANSLATE_NOOP("DBG", "Loading plugins..."));
    pluginloadall(plugindir);
    dputs(QT_TRANSLATE_NOOP("DBG", "Handling command line..."));
    //handle command line
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if(argc == 2) //1 argument (init filename)
        DbgCmdExec(StringUtils::Utf16ToUtf8(StringUtils::sprintf(L"init \"%s\"", argv[1])).c_str());
    else if(argc == 3)  //2 arguments (init filename, cmdline)
        DbgCmdExec(StringUtils::Utf16ToUtf8(StringUtils::sprintf(L"init \"%s\", \"%s\"", argv[1], argv[2])).c_str());
    else if(argc == 4)  //3 arguments (init filename, cmdline, currentdir)
        DbgCmdExec(StringUtils::Utf16ToUtf8(StringUtils::sprintf(L"init \"%s\", \"%s\", \"%s\"", argv[1], argv[2], argv[3])).c_str());
    else if(argc == 5 && !_wcsicmp(argv[1], L"-a") && !_wcsicmp(argv[3], L"-e"))  //4 arguments (JIT)
        DbgCmdExec(StringUtils::Utf16ToUtf8(StringUtils::sprintf(L"attach .%s, .%s", argv[2], argv[4])).c_str()); //attach pid, event
    LocalFree(argv);

    dputs(QT_TRANSLATE_NOOP("DBG", "Initialization successful!"));
    bIsStopped = false;
    return nullptr;
}

/**
@brief This function is called when the user closes the debugger.
*/
extern "C" DLL_EXPORT void _dbg_dbgexitsignal()
{
    dputs(QT_TRANSLATE_NOOP("DBG", "Stopping running debuggee..."));
    cbDebugStop(0, 0);
    dputs(QT_TRANSLATE_NOOP("DBG", "Waiting for the debuggee to be stopped..."));
    if(!waitfor(WAITID_STOP, 10000)) //after this, debugging stopped
    {
        dputs(QT_TRANSLATE_NOOP("DBG", "The debuggee does not close after 10 seconds. Probably the debugger state has been corrupted."));
    }
    dputs(QT_TRANSLATE_NOOP("DBG", "Aborting scripts..."));
    scriptabort();
    dputs(QT_TRANSLATE_NOOP("DBG", "Unloading plugins..."));
    pluginunloadall();
    dputs(QT_TRANSLATE_NOOP("DBG", "Stopping command thread..."));
    bStopCommandLoopThread = true;
    MsgFreeStack(gMsgStack);
    WaitForThreadTermination(hCommandLoopThread);
    dputs(QT_TRANSLATE_NOOP("DBG", "Cleaning up allocated data..."));
    cmdfree();
    varfree();
    yr_finalize();
    Capstone::GlobalFinalize();
    dputs(QT_TRANSLATE_NOOP("DBG", "Cleaning up wait objects..."));
    waitdeinitialize();
    dputs(QT_TRANSLATE_NOOP("DBG", "Cleaning up debugger threads..."));
    dbgstop();
    dputs(QT_TRANSLATE_NOOP("DBG", "Saving notes..."));
    char* text = nullptr;
    GuiGetGlobalNotes(&text);
    if(text)
    {
        FileHelper::WriteAllText(notesFile, String(text));
        BridgeFree(text);
    }
    else
        DeleteFileW(StringUtils::Utf8ToUtf16(notesFile).c_str());
    dputs(QT_TRANSLATE_NOOP("DBG", "Exit signal processed successfully!"));
#ifdef ENABLE_MEM_TRACE
    if(!memleaks())
        DeleteFileW(StringUtils::Utf8ToUtf16(alloctrace).c_str());
#endif //ENABLE_MEM_TRACE
    bIsStopped = true;
}

extern "C" DLL_EXPORT bool _dbg_dbgcmddirectexec(const char* cmd)
{
    if(cmddirectexec(cmd) == false)
        return false;
    return true;
}

bool dbgisstopped()
{
    return bIsStopped;
}
