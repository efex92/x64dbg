#ifndef TRACERECORD_H
#define TRACERECORD_H
#include "_global.h"
#include "_dbgfunctions.h"

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
     * TraceRecordWordWithAccessTypeAndAddr: 32-bit, YYYYXXXX  XXZZZZZZ PPPPPPPP PPPPPPPP YYYY:=TraceRecordByteType_4bit, XXXXXX:=Access Count(6bit), ZZZZZZ:=Write Count(6bit), PPPPPPPP PPPPPPPP:=RVA Of Last Visited Instruction
     * Other: reserved for future expanding
     **************************************************************/
    enum TraceRecordType
    {
        TraceRecordNone,
        TraceRecordBitExec,
        TraceRecordByteWithExecTypeAndCounter,
        TraceRecordWordWithExecTypeAndCounter,
        TraceRecordWordWithAccessTypeAndAddr
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

    void TraceExecute(duint address, duint size);
    //void TraceAccess(duint address, unsigned char size, TraceRecordByteType accessType);

    unsigned int getHitCount(duint address);
    TraceRecordByteType getByteType(duint address);
    void increaseInstructionCounter();

    void saveToDb(JSON root);
    void loadFromDb(JSON root);
private:
    enum TraceRecordByteType_2bit
    {
        _InstructionBody = 0,
        _InstructionHeading = 1,
        _InstructionTailing = 2,
        _InstructionOverlapped = 3
    };

    struct TraceRecordPage
    {
        void* rawPtr;
        duint rva;
        TraceRecordRunTraceInfo runTraceInfo;
        TraceRecordType dataType;
        unsigned int moduleIndex;
    };

    //Key := page base, value := trace record raw data
    std::unordered_map<duint, TraceRecordPage> TraceRecord;
    std::vector<std::string> ModuleNames;
    unsigned int getModuleIndex(const String & moduleName);
    unsigned int instructionCounter;
};

extern TraceRecordManager TraceRecord;
void _dbg_dbgtraceexecute(duint CIP);

//exported to bridge
unsigned int _dbg_dbggetTraceRecordHitCount(duint address);
TRACERECORDBYTETYPE _dbg_dbggetTraceRecordByteType(duint address);
bool _dbg_dbgsetTraceRecordType(duint pageAddress, TRACERECORDTYPE type);
TRACERECORDTYPE _dbg_dbggetTraceRecordType(duint pageAddress);

#endif // TRACERECORD_H
