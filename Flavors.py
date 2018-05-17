import os


# apk 文件结构
# before signing: Contents of Zip entries | Centrol Directory | End of Central Diractory
# after  signing: Contents of Zip entries | Apk Signing Block | Centrol Directory | End of Central Diractory
# V2签名目前保护APK文件所有信息，但是通过V2签名验证源码看，APK Signing Block 可以插入其他信息，但是要注意插入信息后，对便宜量重新赋值
class SignatureMagicInfo:

    def __init__(self, eocdStart = 0, cdStart = 0, sigBlockStart = 0, sigBlockSize = 0, apkBytes = bytearray()):
        self.eocdStart = eocdStart
        self.cdStart = cdStart
        self.sigBlockStart = sigBlockStart
        self.sigBlockSize = sigBlockSize
        self.apkBytes = apkBytes

        self.existIdValues = {}

        self.channelIdValues = {}

    def containsMagicId(self):
        '''
            是否是Scheme V2 签名
        '''
        return '0x7109871a' in self.existIdValues
    
    def containsChanneledInfo(self):
        '''
            是否已经注入过channel信息
        '''
        return 'channel' in self.channelIdValues

    def clearChannelInfo(self):
        '''
            移除已经注入的channel信息
        '''
        # 如果没有自定义的channel id 那么就不用clear了    
        if not self.containsChanneledInfo():
            return self
        
        channelBytesSize = 8 + 4 + len(self.channelIdValues['channel'].encode('utf-8'))
        
        # revert centrol directionary start
        new_cdStart = self.cdStart - channelBytesSize
        new_cdStartHex = hex(new_cdStart).replace('0x', '').zfill(16)
        new_cdStartBytes = [int('0x'+new_cdStartHex[2*x:2*x+2], 16) for x in range(8)][::-1]

        self.apkBytes[self.eocdStart+16] = new_cdStartBytes[0]
        self.apkBytes[self.eocdStart+17] = new_cdStartBytes[1]
        self.apkBytes[self.eocdStart+18] = new_cdStartBytes[2]
        self.apkBytes[self.eocdStart+19] = new_cdStartBytes[3]

        # revert sig block size
        new_sigBlockSize = self.sigBlockSize - channelBytesSize
        new_sigBlockSizeHex = hex(new_sigBlockSize).replace('0x', '').zfill(16)
        new_sigBlockSizeBytes = [int('0x'+new_sigBlockSizeHex[2*x:2*x+2], 16) for x in range(8)][::-1]

        for i in range(8):
            self.apkBytes[self.cdStart - 24 + i] = new_sigBlockSizeBytes[i]
            self.apkBytes[self.cdStart - self.sigBlockSize - 8 + i] = new_sigBlockSizeBytes[i]

        new_apkBytes = self.apkBytes[0:self.channelIdValues['start']]
        new_apkBytes.extend(self.apkBytes[self.channelIdValues['start'] + channelBytesSize:])
        
        return getApkSignatureMagicInfoFromBytes(new_apkBytes)

    def writeChannelName(self, channelName):
        '''
            写入渠道信息
        '''
        channelStr = '{"channel":"%s"}'%channelName
        return self.writeChannelString(channelStr)

    def writeChannelString(self, channelStr):
        '''
            写入自定义字符串
        '''
        # 如果之前已经修改过了，必须flush掉，否则抛出异常
        if self.containsChanneledInfo():
            raise Exception('Must Flush Current Changes Or Has Exist A Channel Info')
        
        customIdValuePairBytes = SignatureMagicInfo.__wrapCustomIdValuePair(channelStr)

        # 修改 Centrol Directory Start Bytes Value
        new_cdStart = self.cdStart + len(customIdValuePairBytes)
        new_cdStartHex = hex(new_cdStart).replace('0x', '').zfill(8)
        new_cdStartBytes = [int('0x'+new_cdStartHex[2*x:2*x+2], 16) for x in range(4)][::-1]
        # 写入新的start覆盖
        self.apkBytes[self.eocdStart+16] = new_cdStartBytes[0]
        self.apkBytes[self.eocdStart+17] = new_cdStartBytes[1]
        self.apkBytes[self.eocdStart+18] = new_cdStartBytes[2]
        self.apkBytes[self.eocdStart+19] = new_cdStartBytes[3]

        # 修改 Signing Block Size Bytes Value
        new_sigBlockSize = self.sigBlockSize + len(customIdValuePairBytes)
        new_sigBlockSizeHex = hex(new_sigBlockSize).replace('0x', '').zfill(16)
        new_sigBlockSizeBytes = [int('0x'+new_sigBlockSizeHex[2*x:2*x+2], 16) for x in range(8)][::-1]
        # 写入新的size覆盖
        for i in range(8):
            self.apkBytes[self.cdStart - 24 + i] = new_sigBlockSizeBytes[i]
            self.apkBytes[self.cdStart - self.sigBlockSize - 8 + i] = new_sigBlockSizeBytes[i]

        # wrap channeled apk bytes
        new_apkBytes = self.apkBytes[0:self.channelIdValues['start']]
        new_apkBytes.extend(customIdValuePairBytes)
        new_apkBytes.extend(self.apkBytes[self.channelIdValues['start']:])

        return getApkSignatureMagicInfoFromBytes(new_apkBytes)

    def flush(self, path = None):
        '''
            写入文件
        '''
        if path is None:
            path = 'app_updated.apk'
        with open(path, 'wb') as apk:
            if self.apkBytes is not None:
                apk.write(self.apkBytes)

    @staticmethod
    def __wrapCustomIdValuePair(channelStr):
        # 自定义一个ID
        # 0x77777777
        channelBytes = channelStr.encode('utf-8')
        idBytes = [0x77, 0x77, 0x77, 0x77]

        idAndChannelLength = len(channelBytes) + len(idBytes)

        # zip中数字是小端存储的
        idAndChannelLengthHex = hex(idAndChannelLength).replace('0x', '').zfill(16)
        idAndChannelLengthBytes = [int('0x'+idAndChannelLengthHex[2*x:2*x+2], 16) for x in range(8)][::-1]

        # 封装Custom Id Value 信息
        customIdValuePairBytes = bytearray()
        customIdValuePairBytes.extend(idAndChannelLengthBytes)
        customIdValuePairBytes.extend(bytearray(idBytes))
        customIdValuePairBytes.extend(channelBytes)
        
        return customIdValuePairBytes

def bytesToInt(bytesValue, type):
    '''
        16进制byte数组转int
    '''
    bytesValueHex = '0x'
    for b in bytesValue:
        bytesValueHex += hex(b).replace('0x', '').zfill(2)
    return int(bytesValueHex, type)

def getApkSignatureMagicInfoFromPath(path):
    with open(path, 'rb') as apk:
        apkBytes = bytearray(apk.read())
    
    return getApkSignatureMagicInfoFromBytes(apkBytes)

def getApkSignatureMagicInfoFromBytes(apkBytes):
    '''
        魔数
        0x06054b50 
        大端存储方式
        0x06 0x05 0x4b 0x50
        小端存储方式
        0x50 0x4b 0x05 0x06
        apk包为zip包，zip包是以小端存储的方式存储字节码的
        End of Central Diractory 大小 22 
        所以寻找顺序 0x50,0x4b,0x05,0x06 
    '''

    # find End of Centrol Directory
    for i in range(len(apkBytes)-22):
        if apkBytes[-22 - i] == 0x50 \
            and apkBytes[-21 - i] == 0x4b \
            and apkBytes[-20 - i] == 0x05 \
            and apkBytes[-19 - i] == 0x06:
            break
    eocdStart = len(apkBytes) - 22 - i

    # Centrol Directory Start
    # 小端存储，需要倒序下，再进行转换
    centrolDirectoryStartBytes = apkBytes[eocdStart+16:eocdStart+20][::-1]
    centrolDirectoryStart = bytesToInt(centrolDirectoryStartBytes, 16)

    centrolDirectorySizeBytes = apkBytes[eocdStart+12:eocdStart+16][::-1]
    centrolDirectorySize = bytesToInt(centrolDirectorySizeBytes, 16)

    # 校验 Zip 结构
    if (centrolDirectoryStart + centrolDirectorySize) == eocdStart:
        print('Correct Zip Struct And Find The CentrolDirectoryStartOffset', centrolDirectoryStart)
    else:
        print('Error Zip Struct')
        return None
    
    # Sining Block 结构介绍
    # size of block in bytes (excluding this field) (uint64)
    # Sequence of uint64-length-prefixed ID-value pairs:
    #    ID (uint32)
    #    value (variable-length: length of the pair - 4 bytes)
    # size of block in bytes—same as the very first field (uint64)
    # magic “APK Sig Block 42” (16 bytes)

    # 所以sign block真实大小 = magic(16bytes) + size of block(8bytes) + many idvalue pairs(x bytes)
    # 注意sign block开头的 size of block 并没有算在 sig block 区块内
    # Apk Signing Block 标记
    signBlockBytes = apkBytes[centrolDirectoryStart-16:centrolDirectoryStart]
    if signBlockBytes.decode('utf8') == 'APK Sig Block 42':
        print("Find The Magic Tag 'APK Sig Block 42'")
    else:
        print("Didn't Find The Magic Tag 'APK Sig Block 42'")
        return None
    
    # Apk Signing Block Size
    sigBlockSizeBytes = apkBytes[centrolDirectoryStart-24:centrolDirectoryStart-16][::-1]
    sigBlockSize = bytesToInt(sigBlockSizeBytes, 16)
    # Apk Signing Block Start
    sigBlockStart = centrolDirectoryStart - sigBlockSize - 8

    # APK Signature Info
    sigInfo = SignatureMagicInfo(
        eocdStart=eocdStart,
        cdStart=centrolDirectoryStart,
        sigBlockStart=sigBlockStart,
        sigBlockSize=sigBlockSize,
        apkBytes=apkBytes
    )
    
    # Get All id-value pairs In The Apk
    start = sigBlockStart + 8
    while True:
        # totallength(8) + id(4) + value(x)
        # id-value length
        idValuePairTotalLength = bytesToInt(apkBytes[start:start+8][::-1], 16)

        # id hex value
        sigIdBytes = apkBytes[start+8:start+12][::-1]
        sigIdHex = '0x'
        for value in sigIdBytes:
            sigIdHex += hex(value).replace('0x','').zfill(2)

        sigInfo.existIdValues[sigIdHex] = apkBytes[start+8+4:start+8+idValuePairTotalLength]
        if sigIdHex == '0x7109871a':
            # Magic Id Apk Signature 
            # 同时记录我们的自定义的idvalue pair的起始位置
            print('find the magic id ',idValuePairTotalLength)
            sigInfo.channelIdValues['start'] = start + idValuePairTotalLength + 8
        elif sigIdHex == '0x77777777':
            # 自定义的Channel信息
            sigInfo.channelIdValues['id'] = '0x77777777'
            sigInfo.channelIdValues['channel'] = apkBytes[start+12:start+8+idValuePairTotalLength].decode('utf-8')

        start += 8 + idValuePairTotalLength
        if start >= centrolDirectoryStart - 24:
            break

    return sigInfo


if __name__ == '__main__':
    sigInfo = getApkSignatureMagicInfoFromPath('app.apk')
    print(list(sigInfo.existIdValues.keys()))
    print(sigInfo.channelIdValues)
    if sigInfo.containsMagicId() and not sigInfo.containsChanneledInfo():
        print('apk has no channel so flush a channel')
        sigInfo.writeChannelName('baidu').flush('app_channel.apk')
    else:
        print('apk has flushed channel info so clear channel')
        sigInfo.clearChannelInfo().writeChannelName('Test').flush('app_nochannel.apk')  
