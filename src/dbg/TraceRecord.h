#ifndef TRACERECORD_H
#define TRACERECORD_H
#include "_global.h"
#include "_dbgfunctions.h"
#include "debugger.h"
#include "capstone_wrapper.h"

class TraceRecordManager
{
public:
    enum TraceRecordByteType
    {
        InstructionBody = 0,
        InstructionHeading = 1,
        InstructionTailing = 2,
        InstructionOverlapped = 3, // The byte was executed with differing instruction base addresses
        DataByte = 4,  // This and the following is not implemented yet.
        DataWord = 5,
        DataDWord = 6,
        DataQWord = 7,
        DataFloat = 8,
        DataDouble = 9,
        DataLongDouble = 10,
        DataXMM = 11,
        DataYMM = 12,
        DataMMX = 13,
        DataMixed = 14, //the byte is accessed in multiple ways
        InstructionDataMixed = 15 //the byte is both executed and written
    };

    /***************************************************************
     * Trace record data layout
     * TraceRecordNonoe: disable trace record
     * TraceRecordBitExec: single-bit, executed.
     * TraceRecordByteWithExecTypeAndCounter: 8-bit, YYXXXXXX YY:=TraceRecordByteType_2bit, XXXXXX:=Hit count(6bit)
     * TraceRecordWordWithExecTypeAndCounter: 16-bit, YYXXXXXX XXXXXXXX YY:=TraceRecordByteType_2bit, XX:=Hit count(14bit)
     * TraceRecordDWordWithAccessTypeAndAddr: 32-bit, YYYYXXXX  XXZZZZZZ PPPPPPPP PPPPPPPP YYYY:=TraceRecordByteType_4bit, XXXXXX:=Access Count(6bit), ZZZZZZ:=Write Count(6bit), PPPPPPPP PPPPPPPP:=RVA Of Last Visited Instruction
     * Other: reserved for future expanding
     **************************************************************/
    enum TraceRecordType
    {
        TraceRecordNone,
        TraceRecordBitExec,
        TraceRecordByteWithExecTypeAndCounter,
        TraceRecordWordWithExecTypeAndCounter,
        TraceRecordDWordWithAccessTypeAndAddr
    };

    struct TraceRecordRunTraceInfo
    {
        bool Enabled;
        bool TID;
        bool PID; // Reserved for future multi-process tracing
        bool CodeBytes;
    };

    TraceRecordManager();
    ~TraceRecordManager();
    void clear();

    bool setTraceRecordType(duint pageAddress, TraceRecordType type);
    TraceRecordType getTraceRecordType(duint pageAddress);
    bool createTraceRecordFile(const char* fileName);

    void TraceExecute(duint address, size_t size, Capstone* instruction, unsigned char* instructionDump);
    void TraceAccess(duint address, unsigned char size, TraceRecordByteType accessType);
    void TraceModuleLoad(const char* moduleName, duint base);
    void TraceModuleUnload(const char* moduleName, duint base);
    void TraceThreadCreate(duint TID);
    void TraceThreadExit(duint TID, duint ExitCode);

    unsigned int getHitCount(duint address);
    TraceRecordByteType getByteType(duint address);
    unsigned int getTraceRecordSize(TraceRecordType byteType);

    void saveToDb(JSON root);
    void loadFromDb(JSON root);

    HANDLE mRunTraceFile;
    char mRunTraceFileName[MAX_PATH];
    duint mRunTraceLastTID;
    duint mRunTraceLastIP;
    cs_regs mRunTraceLastWritten;
    unsigned char mRunTraceLastWrittenCount;
    unsigned char mRunTraceLastBuffer[672];
    int mRunTraceLastBufferSize;

private:

    struct TraceRecordPage
    {
        void* rawPtr;
        duint rva;
        TraceRecordRunTraceInfo runTraceInfo;
        TraceRecordType dataType;
        unsigned int moduleIndex;
    };

    struct TraceRecordOperand
    {
        DWORD registerName;
        duint memoryAddress;
        size_t operandSize;
        union
        {
            duint oldValue;
            char* oldValuePtr;
        };
        union
        {
            duint newValue;
            char* newValuePtr;
        };
        char* serialize();
    };

    static unsigned short CapstoneRegToTraceRecordName(x86_reg reg);
    static void CapstoneReadReg(TITAN_ENGINE_CONTEXT_t* context, unsigned short reg, unsigned char* buffer, unsigned int* size);
    void ComposeRunTraceOperandBuffer(TITAN_ENGINE_CONTEXT_t* context, bool rw, unsigned char* buffer, int* bufferSize, const cs_regs* registers, unsigned char registersCount);

    //Key := page base, value := trace record raw data
    std::unordered_map<duint, TraceRecordPage> TraceRecord;
    std::vector<std::string> ModuleNames;
    unsigned int getModuleIndex(const String & moduleName);
};

extern TraceRecordManager TraceRecord;
void _dbg_dbgtraceexecute(duint CIP);

//exported to bridge
unsigned int _dbg_dbggetTraceRecordHitCount(duint address);
TRACERECORDBYTETYPE _dbg_dbggetTraceRecordByteType(duint address);
bool _dbg_dbgsetTraceRecordType(duint pageAddress, TRACERECORDTYPE type);
TRACERECORDTYPE _dbg_dbggetTraceRecordType(duint pageAddress);
bool _dbg_dbgcreateTraceRecordFile(const char* fileName);

#endif // TRACERECORD_H
