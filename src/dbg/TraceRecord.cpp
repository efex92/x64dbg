/**
\file TraceRecord.cpp
\brief Implements the TraceRecordManager class, and manages trace record data.
*/

#include "TraceRecord.h"
#include "module.h"
#include "memory.h"
#include "threading.h"
#include "thread.h"
#include "plugin_loader.h"

TraceRecordManager TraceRecord;

TraceRecordManager::TraceRecordManager()
{
    ModuleNames.emplace_back("");
    mRunTraceFile = NULL;
    memset(mRunTraceFileName, 0, sizeof(mRunTraceFileName));
}

TraceRecordManager::~TraceRecordManager()
{
    clear();
}

void TraceRecordManager::clear()
{
    EXCLUSIVE_ACQUIRE(LockTraceRecord);
    for(auto i = TraceRecord.begin(); i != TraceRecord.end(); ++i)
        efree(i->second.rawPtr, "TraceRecordManager");
    TraceRecord.clear();
    ModuleNames.clear();
    ModuleNames.emplace_back("");
    // Stop run trace
    createTraceRecordFile(nullptr);
}

bool TraceRecordManager::setTraceRecordType(duint pageAddress, TraceRecordType type)
{
    EXCLUSIVE_ACQUIRE(LockTraceRecord);
    pageAddress &= ~((duint)4096 - 1);
    auto pageInfo = TraceRecord.find(ModHashFromAddr(pageAddress));
    if(pageInfo == TraceRecord.end())
    {
        if(type != TraceRecordType::TraceRecordNone)
        {
            TraceRecordPage newPage;
            char modName[MAX_MODULE_SIZE];
            //allocate memory for trace record
            newPage.rawPtr = emalloc(getTraceRecordSize(type), "TraceRecordManager");
            //emalloc always zero the memory
            newPage.dataType = type;
            newPage.runTraceInfo.Enabled = false;
            newPage.runTraceInfo.CodeBytes = false;
            newPage.runTraceInfo.TID = false;
            newPage.runTraceInfo.PID = false;
            if(ModNameFromAddr(pageAddress, modName, true))
            {
                newPage.rva = pageAddress - ModBaseFromAddr(pageAddress);
                newPage.moduleIndex = getModuleIndex(std::string(modName));
            }
            else
                newPage.moduleIndex = ~0;

            auto inserted = TraceRecord.insert(std::make_pair(ModHashFromAddr(pageAddress), newPage));
            if(inserted.second == false) // we failed to insert new page into the map
            {
                efree(newPage.rawPtr);
                return false;
            }
            return true;
        }
        else
            return true;
    }
    else
    {
        if(type == TraceRecordType::TraceRecordNone)
        {
            if(pageInfo != TraceRecord.end())
            {
                efree(pageInfo->second.rawPtr, "TraceRecordManager");
                TraceRecord.erase(pageInfo);
            }
            return true;
        }
        else
            return pageInfo->second.dataType == type; //Can't covert between data types
    }
}

TraceRecordManager::TraceRecordType TraceRecordManager::getTraceRecordType(duint pageAddress)
{
    SHARED_ACQUIRE(LockTraceRecord);
    pageAddress &= ~((duint)4096 - 1);
    auto pageInfo = TraceRecord.find(ModHashFromAddr(pageAddress));
    if(pageInfo == TraceRecord.end())
        return TraceRecordNone;
    else
        return pageInfo->second.dataType;
}

void TraceRecordManager::TraceExecute(duint address, size_t size, Capstone* instruction, unsigned char* instructionDump)
{
    SHARED_ACQUIRE(LockTraceRecord);
    if(size == 0)
        return;
    duint base = address & ~((duint)4096 - 1);
    auto pageInfoIterator = TraceRecord.find(ModHashFromAddr(base));
    if(pageInfoIterator == TraceRecord.end())
        return;
    TraceRecordPage pageInfo;
    pageInfo = pageInfoIterator->second;
    duint offset = address - base;
    bool isMixed;
    if((offset + size) > 4096) // execution crossed page boundary, splitting into 2 sub calls. Noting that byte type may be mislabelled.
    {
        SHARED_RELEASE();
        TraceExecute(address, 4096 - offset, instruction, instructionDump);
        TraceExecute(base + 4096, size + offset - 4096, nullptr, nullptr);
        return;
    }
    isMixed = false;
    switch(pageInfo.dataType)
    {
    case TraceRecordType::TraceRecordNone:
        break;
    case TraceRecordType::TraceRecordBitExec:
        for(unsigned char i = 0; i < size; i++)
            *((char*)pageInfo.rawPtr + (i + offset) / 8) |= 1 << ((i + offset) % 8);
        break;

    case TraceRecordType::TraceRecordByteWithExecTypeAndCounter:
        for(unsigned char i = 0; i < size; i++)
        {
            TraceRecordByteType currentByteType;
            if(isMixed)
                currentByteType = TraceRecordByteType::InstructionOverlapped;
            else if(i == 0)
                currentByteType = TraceRecordByteType::InstructionHeading;
            else if(i == size - 1)
                currentByteType = TraceRecordByteType::InstructionTailing;
            else
                currentByteType = TraceRecordByteType::InstructionBody;

            char* data = (char*)pageInfo.rawPtr + offset + i;
            if(*data == 0)
            {
                *data = (char)currentByteType << 6 | 1;
            }
            else
            {
                isMixed |= (*data & 0xC0) >> 6 == currentByteType;
                *data = ((char)currentByteType << 6) | ((*data & 0x3F) == 0x3F ? 0x3F : (*data & 0x3F) + 1);
            }
        }
        if(isMixed)
            for(unsigned char i = 0; i < size; i++)
                *((char*)pageInfo.rawPtr + i + offset) |= 0xC0;
        break;

    case TraceRecordType::TraceRecordWordWithExecTypeAndCounter:
        for(unsigned char i = 0; i < size; i++)
        {
            TraceRecordByteType currentByteType;
            if(isMixed)
                currentByteType = TraceRecordByteType::InstructionOverlapped;
            else if(i == 0)
                currentByteType = TraceRecordByteType::InstructionHeading;
            else if(i == size - 1)
                currentByteType = TraceRecordByteType::InstructionTailing;
            else
                currentByteType = TraceRecordByteType::InstructionBody;

            short* data = (short*)pageInfo.rawPtr + offset + i;
            if(*data == 0)
            {
                *data = (char)currentByteType << 14 | 1;
            }
            else
            {
                isMixed |= (*data & 0xC0) >> 6 == currentByteType;
                *data = ((char)currentByteType << 14) | ((*data & 0x3FFF) == 0x3FFF ? 0x3FFF : (*data & 0x3FFF) + 1);
            }
        }
        if(isMixed)
            for(unsigned char i = 0; i < size; i++)
                *((short*)pageInfo.rawPtr + i + offset) |= 0xC000;
        break;

    case TraceRecordType::TraceRecordDWordWithAccessTypeAndAddr:
    {
        char byteType = 0;
        for(unsigned char i = 0; i < size; i++)
        {
            TraceRecordByteType currentByteType;
            if(byteType == 2)
                currentByteType = TraceRecordByteType::InstructionDataMixed;
            else if(byteType == 1)
                currentByteType = TraceRecordByteType::InstructionOverlapped;
            else if(i == 0)
                currentByteType = TraceRecordByteType::InstructionHeading;
            else if(i == size - 1)
                currentByteType = TraceRecordByteType::InstructionTailing;
            else
                currentByteType = TraceRecordByteType::InstructionBody;

            unsigned int* data = (unsigned int*)pageInfo.rawPtr + offset + i;
            unsigned int* data_ip;
#ifdef _WIN64 // RIP is 64-bit, needs four words to store RIP
            data_ip = (unsigned int*)pageInfo.rawPtr + offset + i;
#else //x86, EIP is 32-bit, needs 2 words to store EIP
            data_ip = (unsigned int*)pageInfo.rawPtr + offset + i;
#endif //x86
            //TODO
        }
    }
    break;

    default:
        break;
    }

    if(pageInfo.runTraceInfo.Enabled && mRunTraceFile != NULL && instruction != nullptr)
    {
        /*
        Data format:
        (4 or 2bit:message type)
        {00:Trace entry,1000:Registers dump,1001:Modules dump,1010:Threads dump,1011:User modification, 11xx and 01:Reserved}
        If message type is Trace entry:
        {
        define type PtrSize as 2-bit {00:0 bytes, 01:1 byte, 10:4 bytes, 11:8 bytes}
        (PtrSize sizeOfIP)(1bit TID Presence)(1bit PID Presence)(PtrSize sizeOfOperands) (4bit code byte size)(4bit operand count)
        (IP)(TID)(PID)
        (code bytes)
        (sizeOfOperands sizeOfOperands) //maximum size till here is 42 bytes
        (2bit reserved)(2bit operandtype:{00 register 01 memory(32-bit address) 10 memory(64-bit address) 11 reserved)
        (1bit type:{0 old 1 new})(3bit operandsize:{000 1byte 001 2byte 010 4byte 011 8byte 100 16byte 101 32byte 110 (32-bit size) 111 (64-bit size))
        (2byte operand name) or (DWORD/QWORD memory address)
        (optional sizeOfMemoryOperand)
        (n-byte operand value)
        operand name is defined like two characters to save storage space.
        }
        */
        TITAN_ENGINE_CONTEXT_t context;
        DWORD TID = ThreadGetId(hActiveThread);
        cs_regs regRead, regWrite;
        unsigned char regReadCount = 0, regWriteCount = 0;
        memset(regRead, 0, sizeof(regRead));
        memset(regWrite, 0, sizeof(regWrite));
        if(GetFullContextDataEx(hActiveThread, &context) && instruction->RegsAccess(regRead, &regReadCount, regWrite, &regWriteCount))
        {
            dsint relativeIP = address - mRunTraceLastIP;
            unsigned char operandsBuffer[620];
            unsigned int operandsSize = 0;
            unsigned char* bufferPtr = mRunTraceLastBuffer;
            unsigned char i;
            memset(operandsBuffer, 0, sizeof(operandsBuffer));
            // Process last instruction
            ComposeRunTraceWrittenBuffer(&context, mRunTraceLastOperands + mRunTraceLastOperandsSize, &operandsSize);
            // save written registers
            mRunTraceLastOperandsSize += operandsSize;
            operandsSize = 0;
            // save buffer of last instruction to file
            if(mRunTraceLastOperandsSize == 0)
            {
                //nothing to change. every bit is 0
            }
            else if(mRunTraceLastOperandsSize <= 0xff)
            {
                mRunTraceLastBuffer[0] |= 0x01;
                *bufferPtr = mRunTraceLastOperandsSize;
                bufferPtr++;
            }
#ifdef _WIN64
            else if(mRunTraceLastOperandsSize <= 0xffffffff)
#else //x86
            else
#endif //_WIN64
            {
                mRunTraceLastBuffer[0] |= 0x02;
                memcpy(bufferPtr, &mRunTraceLastOperandsSize, 4);
                bufferPtr += 4;
            }
#ifdef _WIN64
            else
            {
                mRunTraceLastBuffer[0] |= 0x03;
                memcpy(bufferPtr, &mRunTraceLastOperandsSize, 8);
                bufferPtr += 8;
            }
#endif //_WIN64
            if(operandsSize != 0)
            {
                memcpy(bufferPtr, mRunTraceLastBuffer, mRunTraceLastOperandsSize);
                bufferPtr += mRunTraceLastOperandsSize;
            }
            DWORD written = 0;
            if(WriteFile(mRunTraceFile, mRunTraceLastBuffer, bufferPtr - mRunTraceLastBuffer, &written, NULL) == FALSE)
            {
#ifdef _WIN64
                dprintf(QT_TRANSLATE_NOOP("DBG", "Failed to write trace record data to %s (RIP = %p). Run trace will be stopped.\n"), mRunTraceFile, address);
#else //x86
                dprintf(QT_TRANSLATE_NOOP("DBG", "Failed to write trace record data to %s (EIP = %p). Run trace will be stopped.\n"), mRunTraceFile, address);
#endif //_WIN64
                CloseHandle(mRunTraceFile);
                mRunTraceFile = NULL;
                memset(mRunTraceFileName, 0, sizeof(mRunTraceFileName));
                mRunTraceLastIP = 0;
                mRunTraceLastTID = 0;
                memset(&mRunTracePreviousContext, 0, sizeof(mRunTracePreviousContext));
                return;
            }
            // Process current instruction
            // save IP
            if((relativeIP >= -0x80 && relativeIP <= 0x7f) && relativeIP != 0)
            {
                mRunTraceLastBuffer[0] |= 0x10;
                mRunTraceLastBuffer[2] = (unsigned char)relativeIP;
                bufferPtr = mRunTraceLastBuffer + 3;
            }
#ifdef _WIN64 // relative IP can be larger than 32 bits
            else if(relativeIP <= 0x7FFFFFFF && relativeIP >= -0x80000000)
#else //x86 relative IP cannot be larger than 32 bits
            else
#endif //_WIN64
            {
                mRunTraceLastBuffer[0] |= 0x20;
                bufferPtr = mRunTraceLastBuffer + 2;
                *(unsigned int*)bufferPtr = (unsigned int)relativeIP;
                bufferPtr += 4;
            }
#ifdef _WIN64
            else
            {
                mRunTraceLastBuffer[0] |= 0x30;
                bufferPtr = mRunTraceLastBuffer + 2;
                *(unsigned long long*)bufferPtr = relativeIP;
                bufferPtr += 8;
            }
#endif //_WIN64
            // save TID if enabled
            if(TID != mRunTraceLastTID && pageInfo.runTraceInfo.TID)
            {
                // always store TID in 4 bytes
                mRunTraceLastBuffer[0] |= 0x08;
                *(unsigned int*)bufferPtr = TID;
                bufferPtr += 4;
            }
            // store PID here, but this program cannot debug child process right now. PID is always 4 bytes
            // save code bytes if enabled
            if(pageInfo.runTraceInfo.CodeBytes)
            {
                mRunTraceLastBuffer[1] = (instruction->Size() & 0x0F) << 4;
                memcpy(bufferPtr, instructionDump, instruction->Size());
                bufferPtr += instruction->Size();
            }
            // save operand count
            mRunTraceLastBuffer[1] |= (regReadCount + regWriteCount) & 0x0F;
            // save operands
            ComposeRunTraceOperandBuffer(&context, false, mRunTraceLastOperands, &mRunTraceLastOperandsSize, &regRead, regReadCount);
            memcpy(&mRunTracePreviousContext, &context, sizeof(context));
        }
        mRunTraceLastIP = address + instruction->Size();
        mRunTraceLastTID = TID;
    }
}

/**
@brief ComposeRunTraceOperandBuffer Write the registers and content specified in mRunTraceLastWritten, to x64dbg's binary format, in buffer.
@param[in] context The CPU context
@param[in] rw Set the old/new bit in the buffer. false is old data, true is new data.
@param[out] buffer The output buffer.
@param[out] BufferSize Output the buffer size written.
*/
void TraceRecordManager::ComposeRunTraceOperandBuffer(TITAN_ENGINE_CONTEXT_t* context, bool rw, unsigned char* buffer, unsigned int* bufferSize, const cs_regs* registers, unsigned char registersCount)
{
    int operandsSize = 0;
    for(int i = 0; i < registersCount; i++)
    {
        unsigned int registerSize = 0;
        unsigned short operandName = CapstoneRegToTraceRecordName((x86_reg) * registers[i]);
        CapstoneReadReg(context, operandName, buffer + 512, &registerSize);
        memcpy(&buffer[operandsSize + 1], &operandName, 2);
        switch(registerSize)
        {
        case 1:
            break;
        case 2:
            buffer[operandsSize] |= 1;
            break;
        case 4:
            buffer[operandsSize] |= 2;
            break;
        case 8:
            buffer[operandsSize] |= 3;
            break;
        case 16:
            buffer[operandsSize] |= 4;
            break;
        case 32:
            buffer[operandsSize] |= 5;
            break;
        default:
            //TODO
            break;
        }
        if(rw)
            buffer[operandsSize] |= 8;
        operandsSize += 3;
        memcpy(buffer + operandsSize, buffer + 512, registerSize);
        operandsSize += registerSize;
    }
    *bufferSize = operandsSize;
}

void TraceRecordManager::ComposeRunTraceWrittenBuffer(TITAN_ENGINE_CONTEXT_t* context, unsigned char* buffer, unsigned int* bufferSize)
{
    cs_regs writtenRegs;
    unsigned char writtenRegCount = 0;
    memset(&writtenRegs, 0, sizeof(writtenRegs));

    if(mRunTracePreviousContext.cax != context->cax)
    {
        writtenRegs[writtenRegCount] = X86_REG_EAX;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.ccx != context->ccx)
    {
        writtenRegs[writtenRegCount] = X86_REG_ECX;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.cdx != context->cdx)
    {
        writtenRegs[writtenRegCount] = X86_REG_EDX;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.cbx != context->cbx)
    {
        writtenRegs[writtenRegCount] = X86_REG_EBX;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.csp != context->csp)
    {
        writtenRegs[writtenRegCount] = X86_REG_ESP;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.cbp != context->cbp)
    {
        writtenRegs[writtenRegCount] = X86_REG_EBP;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.csi != context->csi)
    {
        writtenRegs[writtenRegCount] = X86_REG_ESI;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.cdi != context->cdi)
    {
        writtenRegs[writtenRegCount] = X86_REG_EDI;
        writtenRegCount++;
    }
#ifdef _WIN64
    if(mRunTracePreviousContext.r10 != context->r10)
    {
        writtenRegs[writtenRegCount] = X86_REG_R10;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.r11 != context->r11)
    {
        writtenRegs[writtenRegCount] = X86_REG_R11;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.r12 != context->r12)
    {
        writtenRegs[writtenRegCount] = X86_REG_R12;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.r13 != context->r13)
    {
        writtenRegs[writtenRegCount] = X86_REG_R13;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.r14 != context->r14)
    {
        writtenRegs[writtenRegCount] = X86_REG_R14;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.r15 != context->r15)
    {
        writtenRegs[writtenRegCount] = X86_REG_R15;
        writtenRegCount++;
    }
#endif //_WIN64
    // No check for RIP
    if(mRunTracePreviousContext.eflags != context->eflags)
    {
        writtenRegs[writtenRegCount] = X86_REG_EFLAGS;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.gs != context->gs)
    {
        writtenRegs[writtenRegCount] = X86_REG_GS;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.fs != context->fs)
    {
        writtenRegs[writtenRegCount] = X86_REG_FS;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.es != context->es)
    {
        writtenRegs[writtenRegCount] = X86_REG_ES;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.ds != context->ds)
    {
        writtenRegs[writtenRegCount] = X86_REG_DS;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.cs != context->cs)
    {
        writtenRegs[writtenRegCount] = X86_REG_CS;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.ss != context->ss)
    {
        writtenRegs[writtenRegCount] = X86_REG_SS;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.dr0 != context->dr0)
    {
        writtenRegs[writtenRegCount] = X86_REG_DR0;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.dr1 != context->dr1)
    {
        writtenRegs[writtenRegCount] = X86_REG_DR1;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.dr2 != context->dr2)
    {
        writtenRegs[writtenRegCount] = X86_REG_DR2;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.dr3 != context->dr3)
    {
        writtenRegs[writtenRegCount] = X86_REG_DR3;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.dr6 != context->dr6)
    {
        writtenRegs[writtenRegCount] = X86_REG_DR6;
        writtenRegCount++;
    }
    if(mRunTracePreviousContext.dr7 != context->dr7)
    {
        writtenRegs[writtenRegCount] = X86_REG_DR7;
        writtenRegCount++;
    }
    ComposeRunTraceOperandBuffer(context, true, buffer, bufferSize, &writtenRegs, writtenRegCount);
}

unsigned int TraceRecordManager::getHitCount(duint address)
{
    SHARED_ACQUIRE(LockTraceRecord);
    duint base = address & ~((duint)4096 - 1);
    auto pageInfoIterator = TraceRecord.find(ModHashFromAddr(base));
    if(pageInfoIterator == TraceRecord.end())
        return 0;
    else
    {
        TraceRecordPage pageInfo = pageInfoIterator->second;
        duint offset = address - base;
        switch(pageInfo.dataType)
        {
        case TraceRecordType::TraceRecordBitExec:
            return ((char*)pageInfo.rawPtr)[offset / 8] & (1 << (offset % 8)) ? 1 : 0;
        case TraceRecordType::TraceRecordByteWithExecTypeAndCounter:
            return ((char*)pageInfo.rawPtr)[offset] & 0x3F;
        case TraceRecordType::TraceRecordWordWithExecTypeAndCounter:
            return ((short*)pageInfo.rawPtr)[offset] & 0x3FFF;
        case TraceRecordType::TraceRecordDWordWithAccessTypeAndAddr:
            return ((unsigned int*)pageInfo.rawPtr)[offset] & 0x0FC00000 >> 22;
        default:
            return 0;
        }
    }
}

unsigned int TraceRecordManager::getTraceRecordSize(TraceRecordType byteType)
{
    switch(byteType)
    {
    default:
        return 0;
    case TraceRecordType::TraceRecordBitExec:
        return 4096 / 8;
    case TraceRecordType::TraceRecordByteWithExecTypeAndCounter:
        return 4096;
    case TraceRecordType::TraceRecordWordWithExecTypeAndCounter:
        return 4096 * 2;
    case TraceRecordType::TraceRecordDWordWithAccessTypeAndAddr:
        return 4096 * 4;
    }
}

TraceRecordManager::TraceRecordByteType TraceRecordManager::getByteType(duint address)
{
    SHARED_ACQUIRE(LockTraceRecord);
    duint base = address & ~((duint)4096 - 1);
    auto pageInfoIterator = TraceRecord.find(ModHashFromAddr(base));
    if(pageInfoIterator == TraceRecord.end())
        return TraceRecordByteType::InstructionHeading;
    else
    {
        TraceRecordPage pageInfo = pageInfoIterator->second;
        duint offset = address - base;
        switch(pageInfo.dataType)
        {
        default:
        case TraceRecordType::TraceRecordBitExec:
            return TraceRecordByteType::InstructionHeading;
        case TraceRecordType::TraceRecordByteWithExecTypeAndCounter:
            return (TraceRecordByteType)((((char*)pageInfo.rawPtr)[offset] & 0xC0) >> 6);
        case TraceRecordType::TraceRecordWordWithExecTypeAndCounter:
            return (TraceRecordByteType)((((short*)pageInfo.rawPtr)[offset] & 0xC000) >> 14);
        case TraceRecordType::TraceRecordDWordWithAccessTypeAndAddr:
            return (TraceRecordByteType)((((unsigned int*)pageInfo.rawPtr)[offset] & 0xF0000000) >> 28);
        }
    }
}

void TraceRecordManager::saveToDb(JSON root)
{
    EXCLUSIVE_ACQUIRE(LockTraceRecord);
    const JSON jsonTraceRecords = json_array();
    for(auto i : TraceRecord)
    {
        JSON jsonObj = json_object();
        if(i.second.moduleIndex != ~0)
        {
            json_object_set_new(jsonObj, "module", json_string(ModuleNames[i.second.moduleIndex].c_str()));
            json_object_set_new(jsonObj, "rva", json_hex(i.second.rva));
        }
        else
        {
            json_object_set_new(jsonObj, "module", json_string(""));
            json_object_set_new(jsonObj, "rva", json_hex(i.first));
        }
        json_object_set_new(jsonObj, "type", json_hex((duint)i.second.dataType));
        auto ptr = (unsigned char*)i.second.rawPtr;
        duint size = getTraceRecordSize(i.second.dataType);
        auto hex = StringUtils::ToCompressedHex(ptr, size);
        json_object_set_new(jsonObj, "data", json_string(hex.c_str()));
        json_array_append_new(jsonTraceRecords, jsonObj);
    }
    if(json_array_size(jsonTraceRecords))
        json_object_set(root, "tracerecord", jsonTraceRecords);

    // Notify garbage collector
    json_decref(jsonTraceRecords);
}

void TraceRecordManager::loadFromDb(JSON root)
{
    EXCLUSIVE_ACQUIRE(LockTraceRecord);
    // get the root object
    const JSON tracerecord = json_object_get(root, "tracerecord");

    // return if nothing found
    if(!tracerecord)
        return;

    size_t i;
    JSON value;
    json_array_foreach(tracerecord, i, value)
    {
        TraceRecordPage currentPage;
        size_t size;
        currentPage.dataType = (TraceRecordType)json_hex_value(json_object_get(value, "type"));
        currentPage.rva = (duint)json_hex_value(json_object_get(value, "rva"));
        size = getTraceRecordSize(currentPage.dataType);
        if(size != 0)
        {
            currentPage.rawPtr = emalloc(size, "TraceRecordManager");
            const char* p = json_string_value(json_object_get(value, "data"));
            std::vector<unsigned char> data;
            if(StringUtils::FromCompressedHex(p, data) && data.size() == size)
            {
                memcpy(currentPage.rawPtr, data.data(), size);
                const char* moduleName = json_string_value(json_object_get(value, "module"));
                duint key;
                if(*moduleName)
                {
                    currentPage.moduleIndex = getModuleIndex(std::string(moduleName));
                    key = currentPage.rva + ModHashFromName(moduleName);
                }
                else
                {
                    currentPage.moduleIndex = ~0;
                    key = currentPage.rva;
                }
                TraceRecord.insert(std::make_pair(key, currentPage));
            }
            else
                efree(currentPage.rawPtr, "TraceRecordManager");
        }
    }
}

bool TraceRecordManager::createTraceRecordFile(const char* fileName)
{
    // Acquire the lock
    EXCLUSIVE_ACQUIRE(LockTraceRecord);
    if(fileName != nullptr)
    {
        HANDLE mRunTraceFile2; // Don't terminate current run trace session if failed to create the new trace record file.
        // Create a new file to store run trace data
        mRunTraceFile2 = CreateFileW(StringUtils::Utf8ToUtf16(fileName).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        // Fail if file creation fails
        if(mRunTraceFile2 == INVALID_HANDLE_VALUE)
            return false;
        // Close previous handle if already open
        if(mRunTraceFile != NULL)
            CloseHandle(mRunTraceFile);
        mRunTraceFile = mRunTraceFile2;
        strcpy_s(mRunTraceFileName, fileName);
        //Initialize run trace states
        mRunTraceLastIP = 0;
        mRunTraceLastTID = 0;
    }
    else
    {
        // fileName is NULL. Stop run trace.
        if(mRunTraceFile != NULL)
        {
            memset(mRunTraceFileName, 0, sizeof(mRunTraceFileName));
            CloseHandle(mRunTraceFile);
            mRunTraceFile = NULL;
        }
    }
}

unsigned int TraceRecordManager::getModuleIndex(const String & moduleName)
{
    auto iterator = std::find(ModuleNames.begin(), ModuleNames.end(), moduleName);
    if(iterator != ModuleNames.end())
        return (unsigned int)(iterator - ModuleNames.begin());
    else
    {
        ModuleNames.push_back(moduleName);
        return (unsigned int)(ModuleNames.size() - 1);
    }
}

#define MakeRegisterCode(A, B) ((A) << 16 | (B))

unsigned short TraceRecordManager::CapstoneRegToTraceRecordName(x86_reg reg)
{
    switch(reg)
    {
    case X86_REG_CS:
        return MakeRegisterCode('c', 's'); //'cs'
    case X86_REG_DS:
        return MakeRegisterCode('d', 's'); //'ds'
    case X86_REG_EFLAGS:
        return MakeRegisterCode('F', 'L'); //'FL'
#ifdef _WIN64
    case X86_REG_RIP:
#endif //_WIN64
    case X86_REG_EIP:
    case X86_REG_IP:
        return MakeRegisterCode('I', 'P'); //'IP'
    case X86_REG_EIZ:
    case X86_REG_RIZ:
        return MakeRegisterCode('I', 'Z'); //'IZ'
    case X86_REG_ES:
        return MakeRegisterCode('e', 's'); //'es'
    case X86_REG_FPSW:
        return MakeRegisterCode('S', 'W'); //'SW'
    case X86_REG_FS:
        return MakeRegisterCode('f', 's'); //'fs'
    case X86_REG_GS:
        return MakeRegisterCode('g', 's'); //'gs'
#ifdef _WIN64
    case X86_REG_RAX:
#endif //_WIN64
    case X86_REG_EAX:
    case X86_REG_AX:
    case X86_REG_AH:
    case X86_REG_AL:
#ifdef _WIN64
        return MakeRegisterCode('R', 'A'); //'RA'
#else //x86
        return MakeRegisterCode('E', 'A'); //'EA'
#endif //_WIN64
#ifdef _WIN64
    case X86_REG_RBP:
    case X86_REG_BPL:
#endif //_WIN64
    case X86_REG_EBP:
    case X86_REG_BP:
#ifdef _WIN64
        return MakeRegisterCode('R', 'b'); //'Rb'
#else //x86
        return MakeRegisterCode('E', 'b'); //'Eb'
#endif //_WIN64
#ifdef _WIN64
    case X86_REG_RBX:
#endif //_WIN64
    case X86_REG_EBX:
    case X86_REG_BX:
    case X86_REG_BH:
    case X86_REG_BL:
#ifdef _WIN64
        return MakeRegisterCode('R', 'B'); //'RB'
#else //x86
        return MakeRegisterCode('E', 'B'); //'EB'
#endif //_WIN64
#ifdef _WIN64
    case X86_REG_RCX:
#endif //_WIN64
    case X86_REG_ECX:
    case X86_REG_CX:
    case X86_REG_CH:
    case X86_REG_CL:
#ifdef _WIN64
        return MakeRegisterCode('R', 'C'); //'RC'
#else //x86
        return MakeRegisterCode('E', 'C'); //'EC'
#endif //_WIN64
#ifdef _WIN64
    case X86_REG_RDI:
    case X86_REG_DIL:
#endif //_WIN64
    case X86_REG_EDI:
    case X86_REG_DI:
#ifdef _WIN64
        return MakeRegisterCode('R', 'd'); //'Rd'
#else //x86
        return MakeRegisterCode('E', 'd'); //'Ed'
#endif //_WIN64
#ifdef _WIN64
    case X86_REG_RDX:
#endif //_WIN64
    case X86_REG_EDX:
    case X86_REG_DX:
    case X86_REG_DH:
    case X86_REG_DL:
#ifdef _WIN64
        return MakeRegisterCode('R', 'D'); //'RD'
#else //x86
        return MakeRegisterCode('E', 'D'); //'ED'
#endif //_WIN64
#ifdef _WIN64
    case X86_REG_RSI:
    case X86_REG_SIL:
#endif //_WIN64
    case X86_REG_ESI:
    case X86_REG_SI:
#ifdef _WIN64
        return MakeRegisterCode('R', 'S'); //'RS'
#else //x86
        return MakeRegisterCode('E', 'S'); //'ES'
#endif //_WIN64
#ifdef _WIN64
    case X86_REG_RSP:
    case X86_REG_SPL:
#endif //_WIN64
    case X86_REG_ESP:
    case X86_REG_SP:
#ifdef _WIN64
        return MakeRegisterCode('R', 's'); //'Rs'
#else //x86
        return MakeRegisterCode('E', 's'); //'Es'
#endif //_WIN64
    case X86_REG_SS:
        return MakeRegisterCode('s', 's'); //'ss'
    //case X86_REG_CR0:
    //    return MakeRegisterCode('C', 0); //'C 0'
    //case X86_REG_CR1:
    //    return MakeRegisterCode('C', 1); //'C 1'
    //case X86_REG_CR2:
    //    return MakeRegisterCode('C', 2); //'C 2'
    //case X86_REG_CR3:
    //    return MakeRegisterCode('C', 3); //'C 3'
    //case X86_REG_CR4:
    //    return MakeRegisterCode('C', 4); //'C 4'
    //case X86_REG_CR5:
    //    return MakeRegisterCode('C', 5); //'C 5'
    //case X86_REG_CR6:
    //    return MakeRegisterCode('C', 6); //'C 6'
    //case X86_REG_CR7:
    //    return MakeRegisterCode('C', 7); //'C 7'
    //case X86_REG_CR8:
    //    return MakeRegisterCode('C', 8); //'C 8'
    //case X86_REG_CR9:
    //    return MakeRegisterCode('C', 9); //'C 9'
    //case X86_REG_CR10:
    //    return MakeRegisterCode('C', 10); //'C 10'
    //case X86_REG_CR11:
    //    return MakeRegisterCode('C', 11); //'C 11'
    //case X86_REG_CR12:
    //    return MakeRegisterCode('C', 12); //'C 12'
    //case X86_REG_CR13:
    //    return MakeRegisterCode('C', 13); //'C 13'
    //case X86_REG_CR14:
    //    return MakeRegisterCode('C', 14); //'C 14'
    //case X86_REG_CR15:
    //    return MakeRegisterCode('C', 15); //'C 15'
    //case X86_REG_DR0:
    //    return MakeRegisterCode('D', 0); //'D 0'
    //case X86_REG_DR1:
    //    return MakeRegisterCode('D', 1); //'D 1'
    //case X86_REG_DR2:
    //    return MakeRegisterCode('D', 2); //'D 2'
    //case X86_REG_DR3:
    //    return MakeRegisterCode('D', 3); //'D 3'
    //case X86_REG_DR4:
    //    return MakeRegisterCode('D', 4); //'D 4'
    //case X86_REG_DR5:
    //    return MakeRegisterCode('D', 5); //'D 5'
    //case X86_REG_DR6:
    //    return MakeRegisterCode('D', 6); //'D 6'
    //case X86_REG_DR7:
    //    return MakeRegisterCode('D', 7); //'D 7'
    //case X86_REG_DR8:
    //    return MakeRegisterCode('D', 8); //'D 8'
    //case X86_REG_DR9:
    //    return MakeRegisterCode('D', 9); //'D 9'
    //case X86_REG_DR10:
    //    return MakeRegisterCode('D', 10); //'D 10'
    //case X86_REG_DR11:
    //    return MakeRegisterCode('D', 11); //'D 11'
    //case X86_REG_DR12:
    //    return MakeRegisterCode('D', 12); //'D 12'
    //case X86_REG_DR13:
    //    return MakeRegisterCode('D', 13); //'D 13'
    //case X86_REG_DR14:
    //    return MakeRegisterCode('D', 14); //'D 14'
    //case X86_REG_DR15:
    //    return MakeRegisterCode('D', 15); //'D 15'
    case X86_REG_FP0:
        return MakeRegisterCode('f', 0); //'f 0'
    case X86_REG_FP1:
        return MakeRegisterCode('f', 1); //'f 1'
    case X86_REG_FP2:
        return MakeRegisterCode('f', 2); //'f 2'
    case X86_REG_FP3:
        return MakeRegisterCode('f', 3); //'f 3'
    case X86_REG_FP4:
        return MakeRegisterCode('f', 4); //'f 4'
    case X86_REG_FP5:
        return MakeRegisterCode('f', 5); //'f 5'
    case X86_REG_FP6:
        return MakeRegisterCode('f', 6); //'f 6'
    case X86_REG_FP7:
        return MakeRegisterCode('f', 7); //'f 7'
    case X86_REG_K0:
        return MakeRegisterCode('K', 0); //'K 0'
    case X86_REG_K1:
        return MakeRegisterCode('K', 1); //'K 1'
    case X86_REG_K2:
        return MakeRegisterCode('K', 2); //'K 2'
    case X86_REG_K3:
        return MakeRegisterCode('K', 3); //'K 3'
    case X86_REG_K4:
        return MakeRegisterCode('K', 4); //'K 4'
    case X86_REG_K5:
        return MakeRegisterCode('K', 5); //'K 5'
    case X86_REG_K6:
        return MakeRegisterCode('K', 6); //'K 6'
    case X86_REG_K7:
        return MakeRegisterCode('K', 7); //'K 7'
    case X86_REG_MM0:
        return MakeRegisterCode('M', 0); //'M 0'
    case X86_REG_MM1:
        return MakeRegisterCode('M', 1); //'M 1'
    case X86_REG_MM2:
        return MakeRegisterCode('M', 2); //'M 2'
    case X86_REG_MM3:
        return MakeRegisterCode('M', 3); //'M 3'
    case X86_REG_MM4:
        return MakeRegisterCode('M', 4); //'M 4'
    case X86_REG_MM5:
        return MakeRegisterCode('M', 5); //'M 5'
    case X86_REG_MM6:
        return MakeRegisterCode('M', 6); //'M 6'
    case X86_REG_MM7:
        return MakeRegisterCode('M', 7); //'M 7'
    case X86_REG_R8:
    case X86_REG_R8B:
    case X86_REG_R8W:
    case X86_REG_R8D:
        return MakeRegisterCode('R', 8); //'R 8'
    case X86_REG_R9:
    case X86_REG_R9B:
    case X86_REG_R9W:
    case X86_REG_R9D:
        return MakeRegisterCode('R', 9); //'R 9'
    case X86_REG_R10:
    case X86_REG_R10B:
    case X86_REG_R10W:
    case X86_REG_R10D:
        return MakeRegisterCode('R', 10); //'R 10'
    case X86_REG_R11:
    case X86_REG_R11B:
    case X86_REG_R11W:
    case X86_REG_R11D:
        return MakeRegisterCode('R', 11); //'R 11'
    case X86_REG_R12:
    case X86_REG_R12B:
    case X86_REG_R12W:
    case X86_REG_R12D:
        return MakeRegisterCode('R', 12); //'R 12'
    case X86_REG_R13:
    case X86_REG_R13B:
    case X86_REG_R13W:
    case X86_REG_R13D:
        return MakeRegisterCode('R', 13); //'R 13'
    case X86_REG_R14:
    case X86_REG_R14B:
    case X86_REG_R14W:
    case X86_REG_R14D:
        return MakeRegisterCode('R', 14); //'R 14'
    case X86_REG_R15:
    case X86_REG_R15B:
    case X86_REG_R15W:
    case X86_REG_R15D:
        return MakeRegisterCode('R', 15); //'R 15'
    case X86_REG_ST0:
        return MakeRegisterCode('S', 0); //'S 0'
    case X86_REG_ST1:
        return MakeRegisterCode('S', 1); //'S 1'
    case X86_REG_ST2:
        return MakeRegisterCode('S', 2); //'S 2'
    case X86_REG_ST3:
        return MakeRegisterCode('S', 3); //'S 3'
    case X86_REG_ST4:
        return MakeRegisterCode('S', 4); //'S 4'
    case X86_REG_ST5:
        return MakeRegisterCode('S', 5); //'S 5'
    case X86_REG_ST6:
        return MakeRegisterCode('S', 6); //'S 6'
    case X86_REG_ST7:
        return MakeRegisterCode('S', 7); //'S 7'
    case X86_REG_XMM0:
        return MakeRegisterCode('X', 0); //'X 0'
    case X86_REG_XMM1:
        return MakeRegisterCode('X', 1); //'X 1'
    case X86_REG_XMM2:
        return MakeRegisterCode('X', 2); //'X 2'
    case X86_REG_XMM3:
        return MakeRegisterCode('X', 3); //'X 3'
    case X86_REG_XMM4:
        return MakeRegisterCode('X', 4); //'X 4'
    case X86_REG_XMM5:
        return MakeRegisterCode('X', 5); //'X 5'
    case X86_REG_XMM6:
        return MakeRegisterCode('X', 6); //'X 6'
    case X86_REG_XMM7:
        return MakeRegisterCode('X', 7); //'X 7'
    case X86_REG_XMM8:
        return MakeRegisterCode('X', 8); //'X 8'
    case X86_REG_XMM9:
        return MakeRegisterCode('X', 9); //'X 9'
    case X86_REG_XMM10:
        return MakeRegisterCode('X', 10); //'X 10'
    case X86_REG_XMM11:
        return MakeRegisterCode('X', 11); //'X 11'
    case X86_REG_XMM12:
        return MakeRegisterCode('X', 12); //'X 12'
    case X86_REG_XMM13:
        return MakeRegisterCode('X', 13); //'X 13'
    case X86_REG_XMM14:
        return MakeRegisterCode('X', 14); //'X 14'
    case X86_REG_XMM15:
        return MakeRegisterCode('X', 15); //'X 15'
    case X86_REG_XMM16:
        return MakeRegisterCode('X', 16); //'X 16'
    case X86_REG_XMM17:
        return MakeRegisterCode('X', 17); //'X 17'
    case X86_REG_XMM18:
        return MakeRegisterCode('X', 18); //'X 18'
    case X86_REG_XMM19:
        return MakeRegisterCode('X', 19); //'X 19'
    case X86_REG_XMM20:
        return MakeRegisterCode('X', 20); //'X 20'
    case X86_REG_XMM21:
        return MakeRegisterCode('X', 21); //'X 21'
    case X86_REG_XMM22:
        return MakeRegisterCode('X', 22); //'X 22'
    case X86_REG_XMM23:
        return MakeRegisterCode('X', 23); //'X 23'
    case X86_REG_XMM24:
        return MakeRegisterCode('X', 24); //'X 24'
    case X86_REG_XMM25:
        return MakeRegisterCode('X', 25); //'X 25'
    case X86_REG_XMM26:
        return MakeRegisterCode('X', 26); //'X 26'
    case X86_REG_XMM27:
        return MakeRegisterCode('X', 27); //'X 27'
    case X86_REG_XMM28:
        return MakeRegisterCode('X', 28); //'X 28'
    case X86_REG_XMM29:
        return MakeRegisterCode('X', 29); //'X 29'
    case X86_REG_XMM30:
        return MakeRegisterCode('X', 30); //'X 30'
    case X86_REG_XMM31:
        return MakeRegisterCode('X', 31); //'X 31'
    case X86_REG_YMM0:
        return MakeRegisterCode('Y', 0); //'Y 0'
    case X86_REG_YMM1:
        return MakeRegisterCode('Y', 1); //'Y 1'
    case X86_REG_YMM2:
        return MakeRegisterCode('Y', 2); //'Y 2'
    case X86_REG_YMM3:
        return MakeRegisterCode('Y', 3); //'Y 3'
    case X86_REG_YMM4:
        return MakeRegisterCode('Y', 4); //'Y 4'
    case X86_REG_YMM5:
        return MakeRegisterCode('Y', 5); //'Y 5'
    case X86_REG_YMM6:
        return MakeRegisterCode('Y', 6); //'Y 6'
    case X86_REG_YMM7:
        return MakeRegisterCode('Y', 7); //'Y 7'
    case X86_REG_YMM8:
        return MakeRegisterCode('Y', 8); //'Y 8'
    case X86_REG_YMM9:
        return MakeRegisterCode('Y', 9); //'Y 9'
    case X86_REG_YMM10:
        return MakeRegisterCode('Y', 10); //'Y 10'
    case X86_REG_YMM11:
        return MakeRegisterCode('Y', 11); //'Y 11'
    case X86_REG_YMM12:
        return MakeRegisterCode('Y', 12); //'Y 12'
    case X86_REG_YMM13:
        return MakeRegisterCode('Y', 13); //'Y 13'
    case X86_REG_YMM14:
        return MakeRegisterCode('Y', 14); //'Y 14'
    case X86_REG_YMM15:
        return MakeRegisterCode('Y', 15); //'Y 15'
    case X86_REG_YMM16:
        return MakeRegisterCode('Y', 16); //'Y 16'
    case X86_REG_YMM17:
        return MakeRegisterCode('Y', 17); //'Y 17'
    case X86_REG_YMM18:
        return MakeRegisterCode('Y', 18); //'Y 18'
    case X86_REG_YMM19:
        return MakeRegisterCode('Y', 19); //'Y 19'
    case X86_REG_YMM20:
        return MakeRegisterCode('Y', 20); //'Y 20'
    case X86_REG_YMM21:
        return MakeRegisterCode('Y', 21); //'Y 21'
    case X86_REG_YMM22:
        return MakeRegisterCode('Y', 22); //'Y 22'
    case X86_REG_YMM23:
        return MakeRegisterCode('Y', 23); //'Y 23'
    case X86_REG_YMM24:
        return MakeRegisterCode('Y', 24); //'Y 24'
    case X86_REG_YMM25:
        return MakeRegisterCode('Y', 25); //'Y 25'
    case X86_REG_YMM26:
        return MakeRegisterCode('Y', 26); //'Y 26'
    case X86_REG_YMM27:
        return MakeRegisterCode('Y', 27); //'Y 27'
    case X86_REG_YMM28:
        return MakeRegisterCode('Y', 28); //'Y 28'
    case X86_REG_YMM29:
        return MakeRegisterCode('Y', 29); //'Y 29'
    case X86_REG_YMM30:
        return MakeRegisterCode('Y', 30); //'Y 30'
    case X86_REG_YMM31:
        return MakeRegisterCode('Y', 31); //'Y 31'
    case X86_REG_ZMM0:
        return MakeRegisterCode('Z', 0); //'Z 0'
    case X86_REG_ZMM1:
        return MakeRegisterCode('Z', 1); //'Z 1'
    case X86_REG_ZMM2:
        return MakeRegisterCode('Z', 2); //'Z 2'
    case X86_REG_ZMM3:
        return MakeRegisterCode('Z', 3); //'Z 3'
    case X86_REG_ZMM4:
        return MakeRegisterCode('Z', 4); //'Z 4'
    case X86_REG_ZMM5:
        return MakeRegisterCode('Z', 5); //'Z 5'
    case X86_REG_ZMM6:
        return MakeRegisterCode('Z', 6); //'Z 6'
    case X86_REG_ZMM7:
        return MakeRegisterCode('Z', 7); //'Z 7'
    case X86_REG_ZMM8:
        return MakeRegisterCode('Z', 8); //'Z 8'
    case X86_REG_ZMM9:
        return MakeRegisterCode('Z', 9); //'Z 9'
    case X86_REG_ZMM10:
        return MakeRegisterCode('Z', 10); //'Z 10'
    case X86_REG_ZMM11:
        return MakeRegisterCode('Z', 11); //'Z 11'
    case X86_REG_ZMM12:
        return MakeRegisterCode('Z', 12); //'Z 12'
    case X86_REG_ZMM13:
        return MakeRegisterCode('Z', 13); //'Z 13'
    case X86_REG_ZMM14:
        return MakeRegisterCode('Z', 14); //'Z 14'
    case X86_REG_ZMM15:
        return MakeRegisterCode('Z', 15); //'Z 15'
    case X86_REG_ZMM16:
        return MakeRegisterCode('Z', 16); //'Z 16'
    case X86_REG_ZMM17:
        return MakeRegisterCode('Z', 17); //'Z 17'
    case X86_REG_ZMM18:
        return MakeRegisterCode('Z', 18); //'Z 18'
    case X86_REG_ZMM19:
        return MakeRegisterCode('Z', 19); //'Z 19'
    case X86_REG_ZMM20:
        return MakeRegisterCode('Z', 20); //'Z 20'
    case X86_REG_ZMM21:
        return MakeRegisterCode('Z', 21); //'Z 21'
    case X86_REG_ZMM22:
        return MakeRegisterCode('Z', 22); //'Z 22'
    case X86_REG_ZMM23:
        return MakeRegisterCode('Z', 23); //'Z 23'
    case X86_REG_ZMM24:
        return MakeRegisterCode('Z', 24); //'Z 24'
    case X86_REG_ZMM25:
        return MakeRegisterCode('Z', 25); //'Z 25'
    case X86_REG_ZMM26:
        return MakeRegisterCode('Z', 26); //'Z 26'
    case X86_REG_ZMM27:
        return MakeRegisterCode('Z', 27); //'Z 27'
    case X86_REG_ZMM28:
        return MakeRegisterCode('Z', 28); //'Z 28'
    case X86_REG_ZMM29:
        return MakeRegisterCode('Z', 29); //'Z 29'
    case X86_REG_ZMM30:
        return MakeRegisterCode('Z', 30); //'Z 30'
    case X86_REG_ZMM31:
        return MakeRegisterCode('Z', 31); //'Z 31'
    default:
        return 0; // '\0\0'
    }
}

void TraceRecordManager::CapstoneReadReg(TITAN_ENGINE_CONTEXT_t* context, unsigned short reg, unsigned char* buffer, unsigned int* size)
{
    switch(reg)
    {
#ifdef _WIN64
    case MakeRegisterCode('R', 'a'):
#else //x86
    case MakeRegisterCode('E', 'a'):
#endif //_WIN64
        memcpy(buffer, &context->cax, sizeof(duint));
        size[0] = sizeof(duint);
        return;
#ifdef _WIN64
    case MakeRegisterCode('R', 'b'):
#else //x86
    case MakeRegisterCode('E', 'b'):
#endif //_WIN64
        memcpy(buffer, &context->cbx, sizeof(duint));
        size[0] = sizeof(duint);
        return;
#ifdef _WIN64
    case MakeRegisterCode('R', 'c'):
#else //x86
    case MakeRegisterCode('E', 'c'):
#endif //_WIN64
        memcpy(buffer, &context->ccx, sizeof(duint));
        size[0] = sizeof(duint);
        return;
#ifdef _WIN64
    case MakeRegisterCode('R', 'd'):
#else //x86
    case MakeRegisterCode('E', 'd'):
#endif //_WIN64
        memcpy(buffer, &context->cdx, sizeof(duint));
        size[0] = sizeof(duint);
        return;
#ifdef _WIN64
    case MakeRegisterCode('R', 8):
        memcpy(buffer, &context->r8, sizeof(duint));
        size[0] = sizeof(duint);
        return;
    case MakeRegisterCode('R', 9):
        memcpy(buffer, &context->r9, sizeof(duint));
        size[0] = sizeof(duint);
        return;
    case MakeRegisterCode('R', 10):
        memcpy(buffer, &context->r10, sizeof(duint));
        size[0] = sizeof(duint);
        return;
    case MakeRegisterCode('R', 11):
        memcpy(buffer, &context->r11, sizeof(duint));
        size[0] = sizeof(duint);
        return;
    case MakeRegisterCode('R', 12):
        memcpy(buffer, &context->r12, sizeof(duint));
        size[0] = sizeof(duint);
        return;
    case MakeRegisterCode('R', 13):
        memcpy(buffer, &context->r13, sizeof(duint));
        size[0] = sizeof(duint);
        return;
    case MakeRegisterCode('R', 14):
        memcpy(buffer, &context->r14, sizeof(duint));
        size[0] = sizeof(duint);
        return;
    case MakeRegisterCode('R', 15):
        memcpy(buffer, &context->r15, sizeof(duint));
        size[0] = sizeof(duint);
        return;
#endif //_WIN64
    case MakeRegisterCode('X', 0):
        memcpy(buffer, &context->XmmRegisters[0], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 0):
        memcpy(buffer, &context->YmmRegisters[0], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 1):
        memcpy(buffer, &context->XmmRegisters[1], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 1):
        memcpy(buffer, &context->YmmRegisters[1], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 2):
        memcpy(buffer, &context->XmmRegisters[2], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 2):
        memcpy(buffer, &context->YmmRegisters[2], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 3):
        memcpy(buffer, &context->XmmRegisters[3], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 3):
        memcpy(buffer, &context->YmmRegisters[3], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 4):
        memcpy(buffer, &context->XmmRegisters[4], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 4):
        memcpy(buffer, &context->YmmRegisters[4], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 5):
        memcpy(buffer, &context->XmmRegisters[5], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 5):
        memcpy(buffer, &context->YmmRegisters[5], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 6):
        memcpy(buffer, &context->XmmRegisters[6], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 6):
        memcpy(buffer, &context->YmmRegisters[6], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 7):
        memcpy(buffer, &context->XmmRegisters[7], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 7):
        memcpy(buffer, &context->YmmRegisters[7], 32);
        size[0] = 32;
        return;
#ifdef _WIN64
    case MakeRegisterCode('X', 8):
        memcpy(buffer, &context->XmmRegisters[8], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 8):
        memcpy(buffer, &context->YmmRegisters[8], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 9):
        memcpy(buffer, &context->XmmRegisters[9], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 9):
        memcpy(buffer, &context->YmmRegisters[9], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 10):
        memcpy(buffer, &context->XmmRegisters[10], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 10):
        memcpy(buffer, &context->YmmRegisters[10], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 11):
        memcpy(buffer, &context->XmmRegisters[11], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 11):
        memcpy(buffer, &context->YmmRegisters[11], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 12):
        memcpy(buffer, &context->XmmRegisters[12], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 12):
        memcpy(buffer, &context->YmmRegisters[12], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 13):
        memcpy(buffer, &context->XmmRegisters[13], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 13):
        memcpy(buffer, &context->YmmRegisters[13], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 14):
        memcpy(buffer, &context->XmmRegisters[14], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 14):
        memcpy(buffer, &context->YmmRegisters[14], 32);
        size[0] = 32;
        return;
    case MakeRegisterCode('X', 15):
        memcpy(buffer, &context->XmmRegisters[15], 16);
        size[0] = 16;
        return;
    case MakeRegisterCode('Y', 15):
        memcpy(buffer, &context->YmmRegisters[15], 32);
        size[0] = 32;
        return;
#endif //_WIN64
    default:
        size[0] = 0;
        return;
    }
}

//============== Global functions ========================

void _dbg_dbgtraceexecute(duint CIP)
{
    if(TraceRecord.getTraceRecordType(CIP) != TraceRecordManager::TraceRecordType::TraceRecordNone)
    {
        unsigned char buffer[MAX_DISASM_BUFFER];
        if(MemRead(CIP, buffer, MAX_DISASM_BUFFER))
        {
            Capstone instruction;
            instruction.Disassemble(CIP, buffer, MAX_DISASM_BUFFER);
            TraceRecord.TraceExecute(CIP, instruction.Size(), &instruction, buffer);
        }
        else
        {
            // if we reaches here, then the executable had executed an invalid address. Don't trace it.
        }
    }
}

unsigned int _dbg_dbggetTraceRecordHitCount(duint address)
{
    return TraceRecord.getHitCount(address);
}

TRACERECORDBYTETYPE _dbg_dbggetTraceRecordByteType(duint address)
{
    return (TRACERECORDBYTETYPE)TraceRecord.getByteType(address);
}

bool _dbg_dbgsetTraceRecordType(duint pageAddress, TRACERECORDTYPE type)
{
    return TraceRecord.setTraceRecordType(pageAddress, (TraceRecordManager::TraceRecordType)type);
}

TRACERECORDTYPE _dbg_dbggetTraceRecordType(duint pageAddress)
{
    return (TRACERECORDTYPE)TraceRecord.getTraceRecordType(pageAddress);
}

bool _dbg_dbgcreateTraceRecordFile(const char* fileName)
{
    return TraceRecord.createTraceRecordFile(fileName);
}