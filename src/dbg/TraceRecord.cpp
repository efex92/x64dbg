#include "TraceRecord.h"
#include "capstone_wrapper.h"
#include "module.h"
#include "memory.h"
#include "threading.h"
#include "debugger.h"
#include "thread.h"
#include "plugin_loader.h"

TraceRecordManager TraceRecord;

TraceRecordManager::TraceRecordManager() : instructionCounter(0)
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
            switch(type)
            {
            case TraceRecordBitExec:
                newPage.rawPtr = emalloc(4096 / 8, "TraceRecordManager");
                memset(newPage.rawPtr, 0, 4096 / 8);
                break;
            case TraceRecordByteWithExecTypeAndCounter:
                newPage.rawPtr = emalloc(4096, "TraceRecordManager");
                memset(newPage.rawPtr, 0, 4096);
                break;
            case TraceRecordWordWithExecTypeAndCounter:
                newPage.rawPtr = emalloc(4096 * 2, "TraceRecordManager");
                memset(newPage.rawPtr, 0, 4096 * 2);
                break;
            default:
                return false;
            }
            newPage.dataType = type;
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

void TraceRecordManager::TraceExecute(duint address, size_t size, Capstone* instruction)
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
        TraceExecute(address, 4096 - offset, nullptr);
        TraceExecute(base + 4096, size + offset - 4096, nullptr);
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
        (sizeOfOperands sizeOfOperands)
        (2bit operandtype:{00 register 01 memory(32-bit address) 10 memory(64-bit address) 11 reserved)
        (1bit type:{0 old 1 new})(3bit operandsize:{000 1byte 001 2byte 010 4byte 011 8byte 100 16byte 101 32byte 110 (32-bit size) 111 (64-bit size))
        (2bit reserved)
        (DWORD operand name) or (DWORD/QWORD memory address)
        (optional sizeOfMemoryOperand)
        (n-byte operand value)
        operand name is defined like FourCC, such as '\0\0AL','\0EAX','\0RAX','XMM0'~'XM15','YMM0'~'YM15','\0ST0'~'\0ST7','\0EFL','\0RFL'
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
            unsigned char buffer[256];
            unsigned char* bufferPtr = buffer;
            memset(buffer, 0, sizeof(buffer));
            if((relativeIP >= -0x80 && relativeIP <= 0x7f) && relativeIP != 0)
            {
                buffer[0] |= 0x10;
                buffer[2] = (unsigned char)relativeIP;
                bufferPtr = buffer + 3;
            }
#ifdef _WIN64 // relative IP can be larger than 32 bits
            else if(relativeIP <= 0x7FFFFFFF && relativeIP >= -0x80000000)
#else //x86 relative IP cannot be larger than 32 bits
            else
#endif //_WIN64
            {
                buffer[0] |= 0x20;
                bufferPtr = buffer + 2;
                *(unsigned int*)bufferPtr = (unsigned int)relativeIP;
                bufferPtr += 4;
            }
#ifdef _WIN64
            else
            {
                buffer[0] |= 0x30;
                bufferPtr = buffer + 2;
                *(unsigned long long*)bufferPtr = relativeIP;
                bufferPtr += 8;
            }
#endif //_WIN64
            if(TID != mRunTraceLastTID && pageInfo.runTraceInfo.TID)
            {
                // always store TID in 4 bytes
                buffer[0] |= 0x08;
                *(unsigned int*)bufferPtr = TID;
                bufferPtr += 4;
            }
            // store PID here, but this program cannot debug child process right now.

        }
        mRunTraceLastIP = address + instruction->Size();
        mRunTraceLastTID = TID;
    }
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
        case TraceRecordType::TraceRecordBitExec:
        default:
            return TraceRecordByteType::InstructionHeading;
        case TraceRecordType::TraceRecordByteWithExecTypeAndCounter:
            return (TraceRecordByteType)((((char*)pageInfo.rawPtr)[offset] & 0xC0) >> 6);
        case TraceRecordType::TraceRecordWordWithExecTypeAndCounter:
            return (TraceRecordByteType)((((short*)pageInfo.rawPtr)[offset] & 0xC000) >> 14);
        }
    }
}

void TraceRecordManager::increaseInstructionCounter()
{
    InterlockedIncrement(&instructionCounter);
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
        duint size = 0;
        switch(i.second.dataType)
        {
        case TraceRecordType::TraceRecordBitExec:
            size = 4096 / 8;
            break;
        case TraceRecordType::TraceRecordByteWithExecTypeAndCounter:
            size = 4096;
            break;
        case TraceRecordType::TraceRecordWordWithExecTypeAndCounter:
            size = 4096 * 2;
            break;
        default:
            __debugbreak(); // We have encountered an error condition.
        }
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
        switch(currentPage.dataType)
        {
        case TraceRecordType::TraceRecordBitExec:
            size = 4096 / 8;
            break;
        case TraceRecordType::TraceRecordByteWithExecTypeAndCounter:
            size = 4096;
            break;
        case TraceRecordType::TraceRecordWordWithExecTypeAndCounter:
            size = 4096 * 2;
            break;
        default:
            size = 0;
            break;
        }
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


DWORD TraceRecordManager::CapstoneRegToTraceRecordName(x86_reg reg)
{
    switch(reg)
    {
    case X86_REG_EFLAGS:
        return 'F' << 24 | 'L' << 16 | 'A' << 8 | 'G'; // 'FLAG'
#ifdef _WIN64
    case X86_REG_RAX:
        return 'R' << 16 | 'A' << 8 | 'X'; // '\0RAX'
    case X86_REG_RBP:
    case X86_REG_BPL:
        return 'R' << 16 | 'B' << 8 | 'P'; // '\0RBP'
    case X86_REG_RBX:
        return 'R' << 16 | 'B' << 8 | 'X'; // '\0RBX'
    case X86_REG_RCX:
        return 'R' << 16 | 'C' << 8 | 'X'; // '\0RCX'
    case X86_REG_RDI:
    case X86_REG_DIL:
        return 'R' << 16 | 'D' << 8 | 'I'; // '\0RDI'
    case X86_REG_RDX:
        return 'R' << 16 | 'D' << 8 | 'X'; // '\0RDX'
    case X86_REG_RIP:
        return 'R' << 16 | 'I' << 8 | 'P'; // '\0RIP'
    case X86_REG_RIZ:
        return 'R' << 16 | 'I' << 8 | 'Z'; // '\0RIZ'
    case X86_REG_RSI:
    case X86_REG_SIL:
        return 'R' << 16 | 'S' << 8 | 'I'; // '\0RSI'
    case X86_REG_RSP:
    case X86_REG_SPL:
        return 'R' << 16 | 'S' << 8 | 'P'; // '\0RSP'
    case X86_REG_R8:
    case X86_REG_R8B:
    case X86_REG_R8W:
    case X86_REG_R8D:
        return 'R' << 8 | '8'; // '\0\0R8'
    case X86_REG_R9:
    case X86_REG_R9B:
    case X86_REG_R9W:
    case X86_REG_R9D:
        return 'R' << 8 | '9'; // '\0\0R9'
    case X86_REG_R10:
    case X86_REG_R10B:
    case X86_REG_R10W:
    case X86_REG_R10D:
        return 'R' << 16 | '1' << 8 | '0'; // '\0R10'
    case X86_REG_R11:
    case X86_REG_R11B:
    case X86_REG_R11W:
    case X86_REG_R11D:
        return 'R' << 16 | '1' << 8 | '1'; // '\0R11'
    case X86_REG_R12:
    case X86_REG_R12B:
    case X86_REG_R12W:
    case X86_REG_R12D:
        return 'R' << 16 | '1' << 8 | '2'; // '\0R12'
    case X86_REG_R13:
    case X86_REG_R13B:
    case X86_REG_R13W:
    case X86_REG_R13D:
        return 'R' << 16 | '1' << 8 | '3'; // '\0R13'
    case X86_REG_R14:
    case X86_REG_R14B:
    case X86_REG_R14W:
    case X86_REG_R14D:
        return 'R' << 16 | '1' << 8 | '4'; // '\0R14'
    case X86_REG_R15:
    case X86_REG_R15B:
    case X86_REG_R15W:
    case X86_REG_R15D:
        return 'R' << 16 | '1' << 8 | '5'; // '\0R15'
#else
    case X86_REG_EAX:
        return 'E' << 16 | 'A' << 8 | 'X'; // '\0EAX'
    case X86_REG_EBP:
        return 'E' << 16 | 'B' << 8 | 'P'; // '\0EBP'
    case X86_REG_EBX:
        return 'E' << 16 | 'B' << 8 | 'X'; // '\0EBX'
    case X86_REG_ECX:
        return 'E' << 16 | 'C' << 8 | 'X'; // '\0ECX'
    case X86_REG_EDI:
        return 'E' << 16 | 'D' << 8 | 'I'; // '\0EDI'
    case X86_REG_EDX:
        return 'E' << 16 | 'D' << 8 | 'X'; // '\0EDX'
    case X86_REG_EIP:
        return 'E' << 16 | 'I' << 8 | 'P'; // '\0EIP'
    case X86_REG_ESI:
        return 'E' << 16 | 'S' << 8 | 'I'; // '\0ESI'
    case X86_REG_ESP:
        return 'E' << 16 | 'S' << 8 | 'P'; // '\0ESP'
#endif
    case X86_REG_AH:
    case X86_REG_AL:
    case X86_REG_AX:
#ifdef _WIN64
        return 'R' << 24 | 'A' << 16 | 'X'; // '\0RAX';
#else //x86
        return 'E' << 24 | 'A' << 16 | 'X'; // '\0EAX';
#endif //_WIN64
    case X86_REG_BH:
    case X86_REG_BL:
    case X86_REG_BX:
#ifdef _WIN64
        return 'R' << 24 | 'B' << 16 | 'X'; // '\0RBX';
#else //x86
        return 'E' << 24 | 'B' << 16 | 'X'; // '\0EBX';
#endif //_WIN64
    case X86_REG_CH:
    case X86_REG_CL:
    case X86_REG_CX:
#ifdef _WIN64
        return 'R' << 24 | 'C' << 16 | 'X'; // '\0RCX';
#else //x86
        return 'E' << 24 | 'C' << 16 | 'X'; // '\0ECX';
#endif //_WIN64
    case X86_REG_DH:
    case X86_REG_DL:
    case X86_REG_DX:
#ifdef _WIN64
        return 'R' << 24 | 'D' << 16 | 'X'; // '\0RDX';
#else //x86
        return 'E' << 24 | 'D' << 16 | 'X'; // '\0EDX';
#endif //_WIN64
    case X86_REG_DI:
#ifdef _WIN64
        return 'R' << 24 | 'D' << 16 | 'I'; // '\0RDI';
#else //x86
        return 'E' << 24 | 'D' << 16 | 'I'; // '\0EDI';
#endif //_WIN64
    case X86_REG_SI:
#ifdef _WIN64
        return 'R' << 24 | 'S' << 16 | 'I'; // '\0RSI';
#else //x86
        return 'E' << 24 | 'S' << 16 | 'I'; // '\0ESI';
#endif //_WIN64
    case X86_REG_BP:
#ifdef _WIN64
        return 'R' << 24 | 'B' << 16 | 'P'; // '\0RBP';
#else //x86
        return 'E' << 24 | 'B' << 16 | 'P'; // '\0EBP';
#endif //_WIN64
    case X86_REG_SP:
#ifdef _WIN64
        return 'R' << 24 | 'S' << 16 | 'P'; // '\0RSP';
#else //x86
        return 'E' << 24 | 'S' << 16 | 'P'; // '\0ESP';
#endif //_WIN64
    case X86_REG_IP:
#ifdef _WIN64
        return 'R' << 24 | 'I' << 16 | 'P'; // '\0RIP';
#else //x86
        return 'E' << 24 | 'I' << 16 | 'P'; // '\0EIP';
#endif //_WIN64
    case X86_REG_EIZ:
        return 'E' << 16 | 'I' << 8 | 'Z'; // '\0EIZ'
    case X86_REG_ES:
        return 'E' << 8 | 'S'; // '\0\0ES'
    case X86_REG_CS:
        return 'C' << 8 | 'S'; // '\0\0CS'
    case X86_REG_DS:
        return 'D' << 8 | 'S'; // '\0\0DS'
    case X86_REG_FPSW:
        return 'F' << 24 | 'P' << 16 | 'S' << 8 | 'W'; // 'FPSW'
    case X86_REG_FS:
        return 'F' << 8 | 'S'; // '\0\0FS'
    case X86_REG_GS:
        return 'G' << 8 | 'S'; // '\0\0GS'
    case X86_REG_SS:
        return 'S' << 8 | 'S'; // '\0\0SS'
    case X86_REG_CR0:
        return 'C' << 16 | 'R' << 8 | '0'; // '\0CR0'
    case X86_REG_CR1:
        return 'C' << 16 | 'R' << 8 | '1'; // '\0CR1'
    case X86_REG_CR2:
        return 'C' << 16 | 'R' << 8 | '2'; // '\0CR2'
    case X86_REG_CR3:
        return 'C' << 16 | 'R' << 8 | '3'; // '\0CR3'
    case X86_REG_CR4:
        return 'C' << 16 | 'R' << 8 | '4'; // '\0CR4'
    case X86_REG_CR5:
        return 'C' << 16 | 'R' << 8 | '5'; // '\0CR5'
    case X86_REG_CR6:
        return 'C' << 16 | 'R' << 8 | '6'; // '\0CR6'
    case X86_REG_CR7:
        return 'C' << 16 | 'R' << 8 | '7'; // '\0CR7'
    case X86_REG_DR0:
        return 'D' << 16 | 'R' << 8 | '0'; // '\0DR0'
    case X86_REG_DR1:
        return 'D' << 16 | 'R' << 8 | '1'; // '\0DR1'
    case X86_REG_DR2:
        return 'D' << 16 | 'R' << 8 | '2'; // '\0DR2'
    case X86_REG_DR3:
        return 'D' << 16 | 'R' << 8 | '3'; // '\0DR3'
    case X86_REG_DR4:
        return 'D' << 16 | 'R' << 8 | '4'; // '\0DR4'
    case X86_REG_DR5:
        return 'D' << 16 | 'R' << 8 | '5'; // '\0DR5'
    case X86_REG_DR6:
        return 'D' << 16 | 'R' << 8 | '6'; // '\0DR6'
    case X86_REG_DR7:
        return 'D' << 16 | 'R' << 8 | '7'; // '\0DR7'
#ifdef _WIN64
    case X86_REG_CR8:
        return 'C' << 16 | 'R' << 8 | '8'; // '\0CR8'
    case X86_REG_CR9:
        return 'C' << 16 | 'R' << 8 | '9'; // '\0CR9'
    case X86_REG_CR10:
        return 'C' << 24 | 'R' << 16 | '1' << 8 | '0'; // 'CR10'
    case X86_REG_CR11:
        return 'C' << 24 | 'R' << 16 | '1' << 8 | '1'; // 'CR11'
    case X86_REG_CR12:
        return 'C' << 24 | 'R' << 16 | '1' << 8 | '2'; // 'CR12'
    case X86_REG_CR13:
        return 'C' << 24 | 'R' << 16 | '1' << 8 | '3'; // 'CR13'
    case X86_REG_CR14:
        return 'C' << 24 | 'R' << 16 | '1' << 8 | '4'; // 'CR14'
    case X86_REG_CR15:
        return 'C' << 24 | 'R' << 16 | '1' << 8 | '5'; // 'CR15'
    case X86_REG_DR8:
        return 'D' << 16 | 'R' << 8 | '8'; // '\0DR8'
    case X86_REG_DR9:
        return 'D' << 16 | 'R' << 8 | '9'; // '\0DR9'
    case X86_REG_DR10:
        return 'D' << 24 | 'R' << 16 | '1' << 8 | '0'; // 'DR10'
    case X86_REG_DR11:
        return 'D' << 24 | 'R' << 16 | '1' << 8 | '1'; // 'DR11'
    case X86_REG_DR12:
        return 'D' << 24 | 'R' << 16 | '1' << 8 | '2'; // 'DR12'
    case X86_REG_DR13:
        return 'D' << 24 | 'R' << 16 | '1' << 8 | '3'; // 'DR13'
    case X86_REG_DR14:
        return 'D' << 24 | 'R' << 16 | '1' << 8 | '4'; // 'DR14'
    case X86_REG_DR15:
        return 'D' << 24 | 'R' << 16 | '1' << 8 | '5'; // 'DR15'
#endif //_WIN64
    case X86_REG_FP0:
        return 'F' << 16 | 'P' << 8 | '0'; // '\0FP0'
    case X86_REG_FP1:
        return 'F' << 16 | 'P' << 8 | '1'; // '\0FP1'
    case X86_REG_FP2:
        return 'F' << 16 | 'P' << 8 | '2'; // '\0FP2'
    case X86_REG_FP3:
        return 'F' << 16 | 'P' << 8 | '3'; // '\0FP3'
    case X86_REG_FP4:
        return 'F' << 16 | 'P' << 8 | '4'; // '\0FP4'
    case X86_REG_FP5:
        return 'F' << 16 | 'P' << 8 | '5'; // '\0FP5'
    case X86_REG_FP6:
        return 'F' << 16 | 'P' << 8 | '6'; // '\0FP6'
    case X86_REG_FP7:
        return 'F' << 16 | 'P' << 8 | '7'; // '\0FP7'
    case X86_REG_K0:
        return 'K' << 8 | '0'; // '\0\0K0'
    case X86_REG_K1:
        return 'K' << 8 | '1'; // '\0\0K1'
    case X86_REG_K2:
        return 'K' << 8 | '2'; // '\0\0K2'
    case X86_REG_K3:
        return 'K' << 8 | '3'; // '\0\0K3'
    case X86_REG_K4:
        return 'K' << 8 | '4'; // '\0\0K4'
    case X86_REG_K5:
        return 'K' << 8 | '5'; // '\0\0K5'
    case X86_REG_K6:
        return 'K' << 8 | '6'; // '\0\0K6'
    case X86_REG_K7:
        return 'K' << 8 | '7'; // '\0\0K7'
    case X86_REG_MM0:
        return 'M' << 16 | 'M' << 8 | '0'; // '\0MM0'
    case X86_REG_MM1:
        return 'M' << 16 | 'M' << 8 | '1'; // '\0MM1'
    case X86_REG_MM2:
        return 'M' << 16 | 'M' << 8 | '2'; // '\0MM2'
    case X86_REG_MM3:
        return 'M' << 16 | 'M' << 8 | '3'; // '\0MM3'
    case X86_REG_MM4:
        return 'M' << 16 | 'M' << 8 | '4'; // '\0MM4'
    case X86_REG_MM5:
        return 'M' << 16 | 'M' << 8 | '5'; // '\0MM5'
    case X86_REG_MM6:
        return 'M' << 16 | 'M' << 8 | '6'; // '\0MM6'
    case X86_REG_MM7:
        return 'M' << 16 | 'M' << 8 | '7'; // '\0MM7'
    case X86_REG_ST0:
        return 'S' << 16 | 'T' << 8 | '0'; // '\0ST0'
    case X86_REG_ST1:
        return 'S' << 16 | 'T' << 8 | '1'; // '\0ST1'
    case X86_REG_ST2:
        return 'S' << 16 | 'T' << 8 | '2'; // '\0ST2'
    case X86_REG_ST3:
        return 'S' << 16 | 'T' << 8 | '3'; // '\0ST3'
    case X86_REG_ST4:
        return 'S' << 16 | 'T' << 8 | '4'; // '\0ST4'
    case X86_REG_ST5:
        return 'S' << 16 | 'T' << 8 | '5'; // '\0ST5'
    case X86_REG_ST6:
        return 'S' << 16 | 'T' << 8 | '6'; // '\0ST6'
    case X86_REG_ST7:
        return 'S' << 16 | 'T' << 8 | '7'; // '\0ST7'
    case X86_REG_XMM0:
        return 'X' << 24 | 'M' << 16 | 'M' << 8 | '0'; // 'XMM0'
    case X86_REG_XMM1:
        return 'X' << 24 | 'M' << 16 | 'M' << 8 | '1'; // 'XMM1'
    case X86_REG_XMM2:
        return 'X' << 24 | 'M' << 16 | 'M' << 8 | '2'; // 'XMM2'
    case X86_REG_XMM3:
        return 'X' << 24 | 'M' << 16 | 'M' << 8 | '3'; // 'XMM3'
    case X86_REG_XMM4:
        return 'X' << 24 | 'M' << 16 | 'M' << 8 | '4'; // 'XMM4'
    case X86_REG_XMM5:
        return 'X' << 24 | 'M' << 16 | 'M' << 8 | '5'; // 'XMM5'
    case X86_REG_XMM6:
        return 'X' << 24 | 'M' << 16 | 'M' << 8 | '6'; // 'XMM6'
    case X86_REG_XMM7:
        return 'X' << 24 | 'M' << 16 | 'M' << 8 | '7'; // 'XMM7'
    case X86_REG_XMM8:
        return 'X' << 24 | 'M' << 16 | 'M' << 8 | '8'; // 'XMM8'
    case X86_REG_XMM9:
        return 'X' << 24 | 'M' << 16 | 'M' << 8 | '9'; // 'XMM9'
    case X86_REG_XMM10:
        return 'X' << 24 | 'M' << 16 | '1' << 8 | '0'; // 'XM10'
    case X86_REG_XMM11:
        return 'X' << 24 | 'M' << 16 | '1' << 8 | '1'; // 'XM11'
    case X86_REG_XMM12:
        return 'X' << 24 | 'M' << 16 | '1' << 8 | '2'; // 'XM12'
    case X86_REG_XMM13:
        return 'X' << 24 | 'M' << 16 | '1' << 8 | '3'; // 'XM13'
    case X86_REG_XMM14:
        return 'X' << 24 | 'M' << 16 | '1' << 8 | '4'; // 'XM14'
    case X86_REG_XMM15:
        return 'X' << 24 | 'M' << 16 | '1' << 8 | '5'; // 'XM15'
    case X86_REG_XMM16:
        return 'X' << 24 | 'M' << 16 | '1' << 8 | '6'; // 'XM16'
    case X86_REG_XMM17:
        return 'X' << 24 | 'M' << 16 | '1' << 8 | '7'; // 'XM17'
    case X86_REG_XMM18:
        return 'X' << 24 | 'M' << 16 | '1' << 8 | '8'; // 'XM18'
    case X86_REG_XMM19:
        return 'X' << 24 | 'M' << 16 | '1' << 8 | '9'; // 'XM19'
    case X86_REG_XMM20:
        return 'X' << 24 | 'M' << 16 | '2' << 8 | '0'; // 'XM20'
    case X86_REG_XMM21:
        return 'X' << 24 | 'M' << 16 | '2' << 8 | '1'; // 'XM21'
    case X86_REG_XMM22:
        return 'X' << 24 | 'M' << 16 | '2' << 8 | '2'; // 'XM22'
    case X86_REG_XMM23:
        return 'X' << 24 | 'M' << 16 | '2' << 8 | '3'; // 'XM23'
    case X86_REG_XMM24:
        return 'X' << 24 | 'M' << 16 | '2' << 8 | '4'; // 'XM24'
    case X86_REG_XMM25:
        return 'X' << 24 | 'M' << 16 | '2' << 8 | '5'; // 'XM25'
    case X86_REG_XMM26:
        return 'X' << 24 | 'M' << 16 | '2' << 8 | '6'; // 'XM26'
    case X86_REG_XMM27:
        return 'X' << 24 | 'M' << 16 | '2' << 8 | '7'; // 'XM27'
    case X86_REG_XMM28:
        return 'X' << 24 | 'M' << 16 | '2' << 8 | '8'; // 'XM28'
    case X86_REG_XMM29:
        return 'X' << 24 | 'M' << 16 | '2' << 8 | '9'; // 'XM29'
    case X86_REG_XMM30:
        return 'X' << 24 | 'M' << 16 | '3' << 8 | '0'; // 'XM30'
    case X86_REG_XMM31:
        return 'X' << 24 | 'M' << 16 | '3' << 8 | '1'; // 'XM31'
    case X86_REG_YMM0:
        return 'Y' << 24 | 'M' << 16 | 'M' << 8 | '0'; // 'YMM0'
    case X86_REG_YMM1:
        return 'Y' << 24 | 'M' << 16 | 'M' << 8 | '1'; // 'YMM1'
    case X86_REG_YMM2:
        return 'Y' << 24 | 'M' << 16 | 'M' << 8 | '2'; // 'YMM2'
    case X86_REG_YMM3:
        return 'Y' << 24 | 'M' << 16 | 'M' << 8 | '3'; // 'YMM3'
    case X86_REG_YMM4:
        return 'Y' << 24 | 'M' << 16 | 'M' << 8 | '4'; // 'YMM4'
    case X86_REG_YMM5:
        return 'Y' << 24 | 'M' << 16 | 'M' << 8 | '5'; // 'YMM5'
    case X86_REG_YMM6:
        return 'Y' << 24 | 'M' << 16 | 'M' << 8 | '6'; // 'YMM6'
    case X86_REG_YMM7:
        return 'Y' << 24 | 'M' << 16 | 'M' << 8 | '7'; // 'YMM7'
    case X86_REG_YMM8:
        return 'Y' << 24 | 'M' << 16 | 'M' << 8 | '8'; // 'YMM8'
    case X86_REG_YMM9:
        return 'Y' << 24 | 'M' << 16 | 'M' << 8 | '9'; // 'YMM9'
    case X86_REG_YMM10:
        return 'Y' << 24 | 'M' << 16 | '1' << 8 | '0'; // 'YM10'
    case X86_REG_YMM11:
        return 'Y' << 24 | 'M' << 16 | '1' << 8 | '1'; // 'YM11'
    case X86_REG_YMM12:
        return 'Y' << 24 | 'M' << 16 | '1' << 8 | '2'; // 'YM12'
    case X86_REG_YMM13:
        return 'Y' << 24 | 'M' << 16 | '1' << 8 | '3'; // 'YM13'
    case X86_REG_YMM14:
        return 'Y' << 24 | 'M' << 16 | '1' << 8 | '4'; // 'YM14'
    case X86_REG_YMM15:
        return 'Y' << 24 | 'M' << 16 | '1' << 8 | '5'; // 'YM15'
    case X86_REG_YMM16:
        return 'Y' << 24 | 'M' << 16 | '1' << 8 | '6'; // 'YM16'
    case X86_REG_YMM17:
        return 'Y' << 24 | 'M' << 16 | '1' << 8 | '7'; // 'YM17'
    case X86_REG_YMM18:
        return 'Y' << 24 | 'M' << 16 | '1' << 8 | '8'; // 'YM18'
    case X86_REG_YMM19:
        return 'Y' << 24 | 'M' << 16 | '1' << 8 | '9'; // 'YM19'
    case X86_REG_YMM20:
        return 'Y' << 24 | 'M' << 16 | '2' << 8 | '0'; // 'YM20'
    case X86_REG_YMM21:
        return 'Y' << 24 | 'M' << 16 | '2' << 8 | '1'; // 'YM21'
    case X86_REG_YMM22:
        return 'Y' << 24 | 'M' << 16 | '2' << 8 | '2'; // 'YM22'
    case X86_REG_YMM23:
        return 'Y' << 24 | 'M' << 16 | '2' << 8 | '3'; // 'YM23'
    case X86_REG_YMM24:
        return 'Y' << 24 | 'M' << 16 | '2' << 8 | '4'; // 'YM24'
    case X86_REG_YMM25:
        return 'Y' << 24 | 'M' << 16 | '2' << 8 | '5'; // 'YM25'
    case X86_REG_YMM26:
        return 'Y' << 24 | 'M' << 16 | '2' << 8 | '6'; // 'YM26'
    case X86_REG_YMM27:
        return 'Y' << 24 | 'M' << 16 | '2' << 8 | '7'; // 'YM27'
    case X86_REG_YMM28:
        return 'Y' << 24 | 'M' << 16 | '2' << 8 | '8'; // 'YM28'
    case X86_REG_YMM29:
        return 'Y' << 24 | 'M' << 16 | '2' << 8 | '9'; // 'YM29'
    case X86_REG_YMM30:
        return 'Y' << 24 | 'M' << 16 | '3' << 8 | '0'; // 'YM30'
    case X86_REG_YMM31:
        return 'Y' << 24 | 'M' << 16 | '3' << 8 | '1'; // 'YM31'
    case X86_REG_ZMM0:
        return 'Z' << 24 | 'M' << 16 | 'M' << 8 | '0'; // 'ZMM0'
    case X86_REG_ZMM1:
        return 'Z' << 24 | 'M' << 16 | 'M' << 8 | '1'; // 'ZMM1'
    case X86_REG_ZMM2:
        return 'Z' << 24 | 'M' << 16 | 'M' << 8 | '2'; // 'ZMM2'
    case X86_REG_ZMM3:
        return 'Z' << 24 | 'M' << 16 | 'M' << 8 | '3'; // 'ZMM3'
    case X86_REG_ZMM4:
        return 'Z' << 24 | 'M' << 16 | 'M' << 8 | '4'; // 'ZMM4'
    case X86_REG_ZMM5:
        return 'Z' << 24 | 'M' << 16 | 'M' << 8 | '5'; // 'ZMM5'
    case X86_REG_ZMM6:
        return 'Z' << 24 | 'M' << 16 | 'M' << 8 | '6'; // 'ZMM6'
    case X86_REG_ZMM7:
        return 'Z' << 24 | 'M' << 16 | 'M' << 8 | '7'; // 'ZMM7'
    case X86_REG_ZMM8:
        return 'Z' << 24 | 'M' << 16 | 'M' << 8 | '8'; // 'ZMM8'
    case X86_REG_ZMM9:
        return 'Z' << 24 | 'M' << 16 | 'M' << 8 | '9'; // 'ZMM9'
    case X86_REG_ZMM10:
        return 'Z' << 24 | 'M' << 16 | '1' << 8 | '0'; // 'ZM10'
    case X86_REG_ZMM11:
        return 'Z' << 24 | 'M' << 16 | '1' << 8 | '1'; // 'ZM11'
    case X86_REG_ZMM12:
        return 'Z' << 24 | 'M' << 16 | '1' << 8 | '2'; // 'ZM12'
    case X86_REG_ZMM13:
        return 'Z' << 24 | 'M' << 16 | '1' << 8 | '3'; // 'ZM13'
    case X86_REG_ZMM14:
        return 'Z' << 24 | 'M' << 16 | '1' << 8 | '4'; // 'ZM14'
    case X86_REG_ZMM15:
        return 'Z' << 24 | 'M' << 16 | '1' << 8 | '5'; // 'ZM15'
    case X86_REG_ZMM16:
        return 'Z' << 24 | 'M' << 16 | '1' << 8 | '6'; // 'ZM16'
    case X86_REG_ZMM17:
        return 'Z' << 24 | 'M' << 16 | '1' << 8 | '7'; // 'ZM17'
    case X86_REG_ZMM18:
        return 'Z' << 24 | 'M' << 16 | '1' << 8 | '8'; // 'ZM18'
    case X86_REG_ZMM19:
        return 'Z' << 24 | 'M' << 16 | '1' << 8 | '9'; // 'ZM19'
    case X86_REG_ZMM20:
        return 'Z' << 24 | 'M' << 16 | '2' << 8 | '0'; // 'ZM20'
    case X86_REG_ZMM21:
        return 'Z' << 24 | 'M' << 16 | '2' << 8 | '1'; // 'ZM21'
    case X86_REG_ZMM22:
        return 'Z' << 24 | 'M' << 16 | '2' << 8 | '2'; // 'ZM22'
    case X86_REG_ZMM23:
        return 'Z' << 24 | 'M' << 16 | '2' << 8 | '3'; // 'ZM23'
    case X86_REG_ZMM24:
        return 'Z' << 24 | 'M' << 16 | '2' << 8 | '4'; // 'ZM24'
    case X86_REG_ZMM25:
        return 'Z' << 24 | 'M' << 16 | '2' << 8 | '5'; // 'ZM25'
    case X86_REG_ZMM26:
        return 'Z' << 24 | 'M' << 16 | '2' << 8 | '6'; // 'ZM26'
    case X86_REG_ZMM27:
        return 'Z' << 24 | 'M' << 16 | '2' << 8 | '7'; // 'ZM27'
    case X86_REG_ZMM28:
        return 'Z' << 24 | 'M' << 16 | '2' << 8 | '8'; // 'ZM28'
    case X86_REG_ZMM29:
        return 'Z' << 24 | 'M' << 16 | '2' << 8 | '9'; // 'ZM29'
    case X86_REG_ZMM30:
        return 'Z' << 24 | 'M' << 16 | '3' << 8 | '0'; // 'ZM30'
    case X86_REG_ZMM31:
        return 'Z' << 24 | 'M' << 16 | '3' << 8 | '1'; // 'ZM31'
    default:
        return 0; // '\0\0\0\0'
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
            TraceRecord.increaseInstructionCounter();
            Capstone instruction;
            instruction.Disassemble(CIP, buffer, MAX_DISASM_BUFFER);
            TraceRecord.TraceExecute(CIP, instruction.Size(), &instruction);
        }
        else
        {
            // if we reaches here, then the executable had executed an invalid address. Don't trace it.
        }
    }
    else
        TraceRecord.increaseInstructionCounter();
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