import socket
import struct
#이더넷 헤더를 파싱해주는 함수
def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s",data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x" + ethernet_header[12].hex()

    print("=====ethernet header=====")
    print("src_mac_address: ",ether_src)
    print("dest_mac_address: ", ether_dest)
    print("ip_version", ip_header)
#아이피헤더를 파싱해주는 함수
def parsing_ip_header(data):
    ip_header = struct.unpack("!1c1c1H2c2s1B1B2c4c4c",data[0][14:34]);  #이더넷 헤더 이후의 20바이트를 가져옴 2바이트의 int형은 H, 1바이트의 int형은 B를 사용하였따.
    ip_version = ip_header[0].hex()[0] #4비트정보를 가져오기위해 hex()함수의 인덱스 0을 가져옴 (hex()함수는 string을 반환) 이하 같은방법
    ip_Length = ip_header[0].hex()[1]
    ip_code_point = ip_header[1].hex()[0]
    ip_congestion_notification = ip_header[1].hex()[1]
    ip_total_length = ip_header[2] #2바이트 정수정보를 그대로 저장 이하 같은 방법
    ip_identification = "0x" + ip_header[3].hex() + ip_header[4].hex() #2byte의 hex코드 변환
    ip_flags = ip_header[5].hex()
#flag를 binary로 쪼개서 해당 비트 대입
    flag_bits = byteToBin(int(ip_flags,16))
    ip_reserved_bit = flag_bits[0]
    ip_not_fragments = flag_bits[1]
    ip_fragments = flag_bits[2]
    ip_fragments_offset = flag_bits[3]

    ip_Time_to_live =  ip_header[6]
    ip_protocol = ip_header[7]
    ip_header_checksum = "0x" + ip_header[8].hex() + ip_header[9].hex()
    ip_src_address = convert_ip_address(ip_header[9:13])
    ip_dest_address = convert_ip_address(ip_header[13:17])

    print("=====ip header=====")
    print("ip_header : ", ip_version)
    print("ip_Length : ", ip_Length)
    print("different_sevices_codepoint : ", ip_code_point)
    print("explicit_congestion_notification : ",ip_congestion_notification)
    print("total_length : ", ip_total_length)
    print("identification : ",ip_identification)
    print("flags : 0x", ip_flags)
    print(">>>reserved_bit : ", ip_reserved_bit)
    print(">>>not_fragments  : ",ip_not_fragments)
    print(">>>fragments : ", ip_fragments)
    print(">>>fragments_offset : ", ip_fragments_offset)
    print("Time to live : ", ip_Time_to_live)
    print("protocol : ", ip_protocol)
    print("header_checksum : ", ip_header_checksum)
    print("source_ip_address : ", ip_src_address)
    print("dest_ip_address : ", ip_dest_address)
#만약 프로토콜 넘버가 6이면 tcp header 파싱함수 실행 17이면 udp header 파싱함수 실행
    if ip_protocol==6:
        parsing_tcp_header(data[0][34:54]) # TCP의 옵션빼고 20바이트를 가져옴
    elif ip_protocol==17:
        parsing_udp_header(data[0][34:42]) # UDP의 8바이트 헤더를 가져옴

#tcp header 파싱함수
def parsing_tcp_header(data):
    tcp_header = struct.unpack("!1H1H1I1I1c1c1H2c1H",data);
    tcp_src_port = tcp_header[0]
    tcp_des_port = tcp_header[1]
    tcp_seq_num = tcp_header[2]
    tcp_ack_num = tcp_header[3]
    tcp_header_len = tcp_header[4].hex()[0]
    tcp_flags = tcp_header[4].hex()[1] + tcp_header[5].hex()
    #flag비트를 binary비트로 쪼개준다. 12바이트 이지만 변환함수가 16비트 기준이다.
    flags_bits = byteToBin(int(tcp_flags,16))

    tcp_window_size_value = tcp_header[6]
    tcp_checksum = "0x"+tcp_header[7].hex()+tcp_header[8].hex()
    tcp_urgent_pointer = tcp_header[9]

    print("=====tcp header=====")
    print("src_port : ", tcp_src_port)
    print("des_port : ", tcp_des_port)
    print("seq_num : ", tcp_seq_num)
    print("ack_num : ", tcp_ack_num)
    print("header_len : ", tcp_header_len)
    print("flags : ", tcp_flags)
    print(">>>reserved :", flags_bits[4])
    print(">>>nonce :",flags_bits[7])
    print(">>>cwr :",flags_bits[8])
    print(">>>urgent :", flags_bits[9])
    print(">>>urgent :",flags_bits[10])
    print(">>>ack :",flags_bits[11])
    print(">>>push :",flags_bits[12])
    print(">>>reset :",flags_bits[13])
    print(">>>syn :",flags_bits[14])
    print(">>>fin :",flags_bits[15])
    print("windeow_size_value :",tcp_window_size_value)
    print("checksum : ",tcp_checksum)
    print("urgent_pointer :",tcp_urgent_pointer)
#udp header 파싱함수
def parsing_udp_header(data):
    udp_header = struct.unpack("!1H1H1H2c",data);
    udp_src_port = udp_header[0]
    udp_des_port = udp_header[1]
    udp_leng = udp_header[2]
    udp_checksum ="0x" + udp_header[3].hex() + udp_header[4].hex()

    print("=====udp_header=====")
    print("src_port : ", udp_src_port)
    print("des_port : ", udp_des_port)
    print("leng : ", udp_leng)
    print("header_checksum", udp_checksum)
#binary코드를 hex코드로 바꿔주어 mac address로 변환 시켜주는 함수
def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr
#binary코드를 십진수로 바꾸어 ip주소로 만들어주는 함수
def convert_ip_address(data):
    ip_addr = list()
    for i in data:
        ip_addr.append(str(int(i.hex(),16)))
    ip_addr = ".".join(ip_addr)
    return ip_addr

#byte코드를 binary코드로 바꿔주는 메소드
def byteToBin(hex):
    result = ""
    counter = 16
    mask = 0b1000000000000000

    while counter > 0:
        c = "1" if(hex&mask)== mask else"0"
        result += c
        hex <<= 1
        counter -=1

    return result
#소켓 생성
recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))


# 패킷 캡처
while True:
    print("<<<<<<Packet Capture Start>>>>>>")
    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14]) #14바이트의 데이터
    parsing_ip_header(data)
