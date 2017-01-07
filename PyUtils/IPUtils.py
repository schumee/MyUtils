#coding:utf-8

import os
import re
import sys
import traceback
from collections import defaultdict

IPV4LENGTH = 32
ALL_ONES = (2**IPV4LENGTH)-1

'''五种IP格式'''
#192.168.1.1
IP_PAT1 = '(([1][0-9]{2})|([0-9])|([2](([0-4][0-9])|([5][0-5])))|([1-9][0-9]))';
PATTERN_1 = '^%s[.]%s[.]%s[.]%s$'%(IP_PAT1,IP_PAT1,IP_PAT1,IP_PAT1);

#192.168.1.*
IP_PAT2 = '((([1][0-9]{2})|([0-9])|([2](([0-4][0-9])|([5][0-5])))|([1-9][0-9]))|([*]))'
PATTERN_2 = '^%s[.]%s[.]%s[.]%s$'%(IP_PAT1,IP_PAT1,IP_PAT1,IP_PAT2);

#192.168.1.1/24
IP_PAT3 = '([/](([1-2][0-9])|([0-9])|([3][0-2])))'
PATTERN_3 = '^%s[.]%s[.]%s[.]%s%s$'%(IP_PAT1,IP_PAT1,IP_PAT1,IP_PAT1,IP_PAT3)

#192.168.1.1-10
PATTERN_4 = '^%s[.]%s[.]%s[.]%s[-]%s$'%(IP_PAT1,IP_PAT1,IP_PAT1,IP_PAT1,IP_PAT1)

#192.168.1-10.*
PATTERN_5 = '^%s[.]%s[.]%s[-]%s[.][*]$'%(IP_PAT1,IP_PAT1,IP_PAT1,IP_PAT1)


IP_PATTERN = [PATTERN_1,PATTERN_2,PATTERN_3,PATTERN_4,PATTERN_5]


def ipv42long(ip_str):
    packed_ip = 0
    octets = ip_str.split('.')
    try:
        if len(octets) != 4:
            raise BaseException
        for oc in octets:
                packed_ip = (packed_ip << 8) | int(oc)
    except BaseException, e:
        sys.stderr.write(str(e))
        traceback.print_exc()
    return packed_ip


def long2ipv4(ip_int):
    octets = []
    try:
        for i in range(4):
                octets.insert(0, str(ip_int & 0xFF))
                ip_int >>= 8
    except BaseException, e:
            sys.stderr.write(str(e))
            traceback.print_exc()
    return '.'.join(octets)


def get_ip_section_list(ipRange):
    ip_section_list = ipRange.split(',')
    ip_section_list = [ i.strip() for i in ip_section_list if i ]
    return ip_section_list


def get_ip_pattern(ip_str):
    global IP_PATTERN
    for i in IP_PATTERN:
        if re.match(i, ip_str):
            return i
    return None


def get_ip_list(ip_start, ip_end):
    if type(ip_start) == str: 
        ip_start = ipv42long(ip_start)
    if type(ip_end) == str:
        ip_end = ipv42long(ip_end)
    ip_start_long = ip_start
    ip_end_long = ip_end
    _result = []
    if ip_end_long < ip_start_long:
        return []
    for i in range(ip_start_long, ip_end_long+1):
        _result.append(i)
    return _result
    
#获取掩码位数
def get_ip_cidr(ip_str):
    pattern = '^(.+)/(([1-2][0-9])|([0-9])|([3][0-2]))$'
    result = re.match(pattern, ip_str).groups()
    #print ip_str,result
    ip_cidr = []
    ip_cidr.append(result[0])
    ip_cidr.append(result[1])
    return ip_cidr

#获取网络号
def get_network(ip_str, cidr):
    ip = ipv42long(ip_str)
    cidr = int(cidr)
    submask = 0
    for i in range(32-cidr,32):
        submask += 1<<i
    submask &= ip
    return submask

#获取广播地址
def get_boardcast(ip_str, cidr):
    network = get_network(ip_str, cidr)
    cidr = int(cidr)
    temp_var = 0
    for i in range(0, 32-cidr):
        temp_var += 1<<i
    boardcast = network | temp_var
    return boardcast

'''
获取对应格式的IP列表
   get_ip_list_0
   get_ip_list_1
   get_ip_list_3
   get_ip_list_4
   
0   192.168.1.1
1   192.168.1.*
2   192.168.1-8.*
3   192.168.5.10-120
4   192.168.5.0/24
'''
def get_ip_list_0(ip_str, rtList=False):
    _ip_start = ipv42long(ip_str)
    _ip_end = _ip_start
    if not rtList:
        return get_ip_list(_ip_start, _ip_end)
    else:
        return [_ip_start, _ip_end]


def get_ip_list_1(ip_str, rtList=False):
    _ip_start = ipv42long(ip_str.replace('*','0'))
    _ip_end = ipv42long(ip_str.replace('*','255'))
    if not rtList: 
        return get_ip_list(_ip_start, _ip_end)
    else:
        return [_ip_start, _ip_end]
    

def get_ip_list_2(ip_str, rtList=False):
    '''192.168.1.1/24'''
    _ip_cidr = get_ip_cidr(ip_str)
    #print ip_str,_ip_cidr
    _ip_start = get_network(_ip_cidr[0],_ip_cidr[1])
    _ip_end = get_boardcast(_ip_cidr[0],_ip_cidr[1])
    #print _ip_start,_ip_end
    if not rtList:
        return get_ip_list(_ip_start, _ip_end)
    else:
        return [_ip_start, _ip_end]
    

def get_ip_list_3(ip_str, rtList=False):
    '''192.168.1.1-10'''
    pattern  = '[.]([0-9]{1,3})[-]([0-9]{1,3})$'
    result = re.search(pattern,ip_str).groups()
    prevar = int(result[0])
    nextvar = int(result[1])
    if prevar > nextvar:
        return []
    _ip_start = ipv42long(ip_str.replace('-'+result[1],'')) 
    _ip_end = ipv42long(ip_str.replace(result[0]+'-',''))
    if not rtList:
        return get_ip_list(_ip_start, _ip_end)
    else:
        return [_ip_start, _ip_end]
    

def get_ip_list_4(ip_str, rtList=False):
    '''192.168.1-10.*'''
    pattern = '[.]([0-9]{1,3})[-]([0-9]{1,3})[.][*]'
    result = re.search(pattern, ip_str).groups()
    prevar = int(result[0])
    nextvar = int(result[1])
    if prevar > nextvar:
        return []
    _ip_start = ipv42long(ip_str.replace('-'+result[1]+'.*', '.0'))
    _ip_end = ipv42long(ip_str.replace(result[0]+'-'+result[1]+'.*', result[1]+'.255'))
    if not rtList:
        return get_ip_list(_ip_start, _ip_end)
    else:
        return [_ip_start, _ip_end]

'''
   匹配并获取对应格式的IP列表
'''
def get_range_list_matched(ipRange, rtList = False):
    global IP_PATTERN
    range_list = []
    ip_section_list = ipRange.split(',')
    for i in ip_section_list:
        pattern = get_ip_pattern(i)
        if pattern == IP_PATTERN[0]:
            range_list.append(get_ip_list_0(i, rtList))
        elif pattern == IP_PATTERN[1]:
            range_list.append(get_ip_list_1(i, rtList))
        elif pattern == IP_PATTERN[2]:
            range_list.append(get_ip_list_2(i, rtList))
        elif pattern == IP_PATTERN[3]:
            range_list.append(get_ip_list_3(i, rtList))
        elif pattern == IP_PATTERN[4]:
            range_list.append(get_ip_list_4(i, rtList))
        else:
            continue
    return range_list


'''
1. 检查IP格式是否符合要求
   输入:ipRange = '192.168.1.1,192.168.1.*...'
   ip范围必须是经过格式处理后的以逗号分隔
'''
def validatelpRangeFormat(ipRange):
    global IP_PATTERN
    ip_section_list = ipRange.split(',')
    flag = False
    for i in ip_section_list:
        flag = False
        for j in IP_PATTERN:
            if re.match(j, i):
                flag = True
                break
        if flag == False:
            return False
    return flag


'''
2. 获取IP列表
   输入:ipRange = '192.168.1.1,192.168.1.*...'
   ip范围必须是经过validatelpRangeFormat校验后的
'''
def getIPList(ipRange):
    _ip_list = set()
    range_list = get_range_list_matched(ipRange,False)
    for i in range_list:
        _ip_list.update(i)
    _ip_list = list(_ip_list)
    _ip_list.sort()
    for i,j in enumerate(_ip_list):
        _ip_list[i] = long2ipv4(j)
    return _ip_list


'''
3. 输入ipRange = '192.168.1.1,192.168.1.*,...'
   ip范围必须是经过validatelpRangeFormat校验后的
   如果不合并的话返回的结果和输入的顺序保持一致
   如果要合并IP范围的话，输出的ip起始段递增
'''
def getIPRangeBoundList(ipRange, combined=False, rtNum=False):
    range_list = get_range_list_matched(ipRange,True)
    if combined:
        range_list = combine(range_list)
    if not rtNum:
        for i,j in enumerate(range_list):
            range_list[i][0] = long2ipv4(range_list[i][0])
            range_list[i][1] = long2ipv4(range_list[i][1])
    return  range_list


'''
   合并IP范围段
'''
def combine(range_list):
    range_list = list_sort(range_list)
    result = []
    length = len(range_list)
    for i in range(length):
        if i < length-1:
            if range_list[i+1][0] <= range_list[i][1] and range_list[i+1][1] <= range_list[i][1]:#in
                range_list[i+1][0] = range_list[i][0]
                range_list[i+1][1] = range_list[i][1]
                range_list[i] = []
                continue
            elif range_list[i+1][0] <= range_list[i][1]+1 and range_list[i+1][1] > range_list[i][1]:
                range_list[i+1][0] = range_list[i][0]
                range_list[i+1][1] = range_list[i+1][1]
                range_list[i] = []
                continue
            else:
                result.append(range_list[i])
                continue
        result.append(range_list[-1])
    return result


def list_sort(range_list):
    result_dict = sorted(range_list, key = lambda x:x[0])
    return result_dict


'''list_a:[2-5], list_b:[4-6] return [4-5]'''
def get_intersection(list_a, list_b):
    list_new = list_a + list_b
    list_new.sort()
    start = list_new[1]
    end = list_new[2]
    if start >= list_a[0] and end <= list_a[1] and start >= list_b[0] and end <= list_b[1]:
        return [start, end]
    return None


def get_difference(list_a, list_b):
    intersection = get_intersection(list_a, list_b)
    if intersection is not None:
        result = []
        if intersection == list_a:
            return None
        if intersection[0] > list_a[0]:
            result.append([list_a[0],intersection[0]-1])
        if intersection[1] < list_a[1]:
            result.append([intersection[1]+1, list_a[1]])
        return result
    return [list_a]


'''rangList: [10-100] return 192.168.1.10-100...'''
#处理归并C\D段IP
def ip_bind_CD(start_n, end_n):
    start_var = long2ipv4(start_n).split('.')
    end_var = long2ipv4(end_n).split('.')
    temp = []
    for i in range(4):
        if start_var[i] == end_var[i]:
            temp.append(start_var[i])
        else:
            temp.append(start_var[i]+'-'+end_var[i])
    if len(temp) == 4:
        ip = '.'.join(temp)
        ip = ip.replace('.0-255','.*')
        return ip


#处理归并A\B段IP
def ip_bind_AB(iplist):
    route_map=defaultdict(set)
    for mask,ip in sorted(iplist,reverse=True):
        for i in sorted((k for k in route_map.iterkeys() if k>=mask)):
            ip_set=route_map[i]
            if i==mask:
                if ip in ip_set:
                    break
                if ip^1 in ip_set:
                    ip_set.remove(ip^1)
                    ip=ip/2
                    mask+=1
            else:
                if ip>>i-mask in ip_set:
                    break
        else:
            route_map[mask].add(ip)
    ips = []
    for mask in route_map.iterkeys():
        for ip in route_map[mask]:
            ip=ip<<mask
            ips.append(long2ipv4(ip)+'/'+str(32-mask))
            #for testing
            #print getIPRangeBoundList(long2ipv4(ip)+'/'+str(32-mask))
    return ips


def rangeToIp(start, end):
    count = end - start + 1
    if count == 1:
        return [long2ipv4(start)]
    exp = 1
    while True:
        if count < pow(256,exp):
            break
        exp += 1
    exp -= 1
    ips = []
    if exp == 0:#D段内
        net_start = get_network(long2ipv4(start),24)
        net_end = get_network(long2ipv4(end),24)
        if net_start == net_end:#表明在同一网段
            start_n = start
            end_n = end
            ips.append(ip_bind_CD(start_n, end_n))
        else:
            if divmod(start+1,256)[1] == 0:#x.x.x.255
                start_n = start
                end_n = start
                ips.append(long2ipv4(start))
                ips.append(ip_bind_CD(end_n+1,end))
            else:#一般情况
                start_n = start
                end_n = get_boardcast(long2ipv4(start),24)
                ips.append(ip_bind_CD(start_n, end_n))
                ips.append(ip_bind_CD(end_n+1, end))   
    elif exp == 1:#C段内
        if divmod(start, 256)[1] == 0:#x.x.x.0
            start_n = start
            if divmod(end, 256)[1] == 0:#x.x.a.0
                end_n = end - 1
                ips.append(ip_bind_CD(start_n, end_n))
                ips.append(long2ipv4(end_n+1))
            elif divmod(end+1, 256)[1] == 0:#x.x.x.255
                end_n = end
                ips.append(ip_bind_CD(start_n, end_n))
            else:#一般情况
                end_n = get_boardcast(long2ipv4(end-256),24)
                ips.append(ip_bind_CD(start_n, end_n))
                ips.append(ip_bind_CD(end_n+1,end))
        elif divmod(start+1,256)[1] == 0:#x.x.x.255
            start_n = start
            end_n = start
            ips.append(long2ipv4(start_n))
            start_n = end_n + 1
            if divmod(end, 256)[1] == 0:#x.x.a.0
                end_n = end - 1
                ips.append(ip_bind_CD(start_n, end_n))
                ips.append(long2ipv4(end_n+1))
            elif divmod(end+1, 256)[1] == 0:#x.x.x.255
                end_n = end
                ips.append(ip_bind_CD(start_n, end_n))
            else:#一般情况
                end_n = get_boardcast(long2ipv4(end-256),24)
                ips.append(ip_bind_CD(start_n, end_n))
                ips.append(ip_bind_CD(end_n+1,end))
        else:#x.x.x.x
            start_n = start
            end_n = get_boardcast(long2ipv4(start),24)
            ips.append(ip_bind_CD(start_n, end_n))
            ips.extend(rangeToIp(end_n+1, end))      
    elif exp == 2:#B段内
        temp_iplist = set()
        if start == get_network(long2ipv4(start),16):
            start_n = start
            if end == get_boardcast(long2ipv4(end),16):
                end_n = end
                while start_n < end_n:
                    temp_iplist.add((16,start_n>>16))
                    start_n += 65536
            else:
                end_n = get_boardcast(long2ipv4(end-65536),16)
                while start_n < end_n:
                    temp_iplist.add((16,start_n>>16))
                    start_n += 65536
                ips.extend(rangeToIp(end_n+1,end))
        else:
            start_n = start
            end_n = get_boardcast(long2ipv4(start),16)
            ips.extend(rangeToIp(start_n, end_n))
            start_n = end_n+1
            if end == get_boardcast(long2ipv4(end),16):
                end_n = end
                while start_n < end_n:
                    temp_iplist.add((16,start_n>>16))
                    start_n += 65536
            else:
                end_n = get_boardcast(long2ipv4(end-65536),16)
                while start_n < end_n:
                    temp_iplist.add((16,start_n>>16))
                    start_n += 65536
                ips.extend(rangeToIp(end_n+1,end))
        ips.extend(ip_bind_AB(temp_iplist))

    elif exp == 3:#A段内 
        temp_iplist = set()
        if start == get_network(long2ipv4(start),8):
            start_n = start
            if end == get_boardcast(long2ipv4(end),8):
                end_n = end
                while start_n < end_n:
                    temp_iplist.add((24,start_n>>24))
                    start_n += 16777216
            else:
                end_n = get_boardcast(long2ipv4(end-16777216),8)
                while start_n < end_n:
                    temp_iplist.add((24,start_n>>24))
                    start_n += 16777216
                ips.extend(rangeToIp(end_n+1,end))
        else:
            start_n = start
            end_n = get_boardcast(long2ipv4(start),8)
            ips.extend(rangeToIp(start_n, end_n))
            start_n = end_n+1
            if end == get_boardcast(long2ipv4(end),8):
                end_n = end
                while start_n < end_n:
                    temp_iplist.add((24,start_n>>24))
                    start_n += 16777216
            else:
                end_n = get_boardcast(long2ipv4(end-16777216),16)
                while start_n < end_n:
                    temp_iplist.add((24,start_n>>24))
                    start_n += 16777216
                ips.extend(rangeToIp(end_n+1,end))
        ips.extend(ip_bind_AB(temp_iplist))
    return ips


'''
4. 输入baseIpRange = '192.168.1.*'
   ip范围必须是经过validatelpRangeFormat校验后的
   example:
       输入：'192.168.0.0/15',['192.168.0.0/16']
       输出：['192.169.0.0/16']
'''
def getDifferenceIRange(baseIpRange,minuendIpRange):
    _baseIpRange = getIPRangeBoundList(baseIpRange,True)
    _minuendIpRange = getIPRangeBoundList(','.join(minuendIpRange), True)
    for i,j in enumerate(_minuendIpRange):
            _minuendIpRange[i][0] = ipv42long(_minuendIpRange[i][0])
            _minuendIpRange[i][1] = ipv42long(_minuendIpRange[i][1])
    _baseIpRange[0][0] = ipv42long(_baseIpRange[0][0])
    _baseIpRange[0][1] = ipv42long(_baseIpRange[0][1])
    
    #for testing
    
    for i,var1 in enumerate(_minuendIpRange):
        temp_difference = []
        for j,var2 in enumerate(_baseIpRange):
            difference = get_difference(var2, var1)
            if difference is not None:
                temp_difference.extend(difference)
        if len(temp_difference) is not 0:
            _baseIpRange = temp_difference
        else:
            return None
    '''合并为五种格式之一'''
    #for i in _baseIpRange:
       #print 'AAAA',long2ipv4(i[0])+'-'+long2ipv4(i[1])
    
    combine_ip = []
    for i in _baseIpRange:
        var = rangeToIp(i[0],i[1])
        if var is not None:
            for j in var:
                combine_ip.append(j)
    return combine_ip


'''
5. 格式化IP范围，返回逗号分隔的IP范围
   输入ipRange = '192.168.1.1;  192.168.1.*,...'
'''
def formatIpRange(ipRange):
    format_pattern = '[\s;,]+'
    ipRange = re.sub(format_pattern, ',', ipRange)
    if ipRange is None:
        return None
    ipRange = ipRange.strip(',')
    ipRange_list = ipRange.split(',')
    return ','.join(ipRange_list)

'''
def test():
    var1 = '12.0.0.0/8'
    var2 = ['12.10.25.254','12.10.255.255','12.10.42.23-50']
    list = getDifferenceIRange(var1,var2)
    print list
    var = []
    var.extend(var2)
    var.extend(list)
    print getIPRangeBoundList(','.join(var),True)
    print getDifferenceIRange(var1,list)
'''
if __name__ == '__main__':
    #import time
    #time_start = time.time()
    #getIPList("192.168.0.0/12,192.168.0.0/12,192.168.0.0/12,192.168.0.0/12")
    #test_time()
    #validatelpRangeFormat('192.168.1.1,192.168.1.1')
    #time_char = time.time() - time_start
    #print time_char
    #print ipv42long('1.1.2.0')
    #print ipv42long('2.2.2.0')
    #print rangeToIp3(ipv42long('1.1.1.1'),ipv42long('2.2.2.2'))
    #print getDifferenceIRange('192.168.0.0/15',['192.168.0.0/16',])
    #print ','.join(getIPList('2.2.2-3.*'))    
    #print getDifferenceIRange('192.168.1-10.*',['192.168.2-3.*','192.168.1.100-150','192.168.1.200','192.168.4.100-255','192.168.7.2-10'])
    #print get_boardcast('1.1.1.1',32)
    #print get_network('1.1.1.0',24)
    #sprint long2ipv4(16843009)
    #print validatelpRangeFormat('0.1.1.11')
    #print getIPList('2.2.2.0/24')
    #print getIPRangeBoundList('192.168.1.*,192.168.2-23.*,192.168.1.1',0)
    #print long2ipv4(3232236288L)
    #print getDifferenceIRange('')
    #print get_ip_cidr('1.1.255.2/0')
    #print validatelpRangeFormat('192.168.1.1,1.1.1.1,2.2.2.*,1.1.1-2.*,1.1.1.1-20,1.1.1/21')
    #print getIPList('192.168.1.0-2,192.168.1.1-3')
    #print getIPRangeBoundList('192.168.1.1,192.168.1.*,1.1.1-2.*,1.1.1.0-120,2.2.2.2/24,192.168.1-2.*')
    #print getDifferenceIRange('192.168.1-3.*',['192.4.3.1-255'])
    #print getDifferenceIRange('192.168.6-7.*',['192.168.7.1'])
    #print getDifferenceIRange('192.168.6-7.*',['192.168.6.6','2.2.2.2'])
    #print ','.join(getDifferenceIRange('192.168.1.1/24',['192.168.1.0','192.168.1.4-119','192.168.1.120-125','192.168.1.210-254','192.168.2-2.*']))
    #print formatIpRange(str1)
    #print rangeToIp(ipv42long('1.1.2.254'),ipv42long('192.2.11.254'))
    #print rangeToIp2(ipv42long('1.1.1.1/16'),ipv42long('1.1.1.0-23'))
    #print rangeToIp(ipv42long('192.1.0.0'),ipv42long('192.123.0.1'))
    #print long2ipv4(get_network('192.168.1.2',24))
    #print long2ipv4(get_boardcast('192.168.1.1',24))
    #print get_difference([ipv42long('192.168.7.10'),ipv42long('192.168.10.255')],[ipv42long('192.168.7.10'),ipv42long('192.168.7.255')])
    #print long2ipv4(3232238335L)
    #print rangeToIp(ipv42long('1.0.0.0'),ipv42long('1.1.255.255'))
    #print getIPRangeBoundList('192.0.0.0/10')
    print getIPRangeBoundList('192.168.3.0-255,192.168.2.*',True)
    print rangeToIp(ipv42long('12.10.25.20'),ipv42long('12.10.25.25'))
    #test()