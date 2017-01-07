#coding:utf-8
'''
A tool to generate tcpflag mapping
'''

TCPFLAGS = ['1,FIN', '2,SYN', '4,RST', '8,PSH', '16,ACK', '32,URG', '64,ECE', '128,CWR']
def gen_tcpflag_dict():
    def handleline(x): y=x.split(','); return (int(y[0]),y[1])
    _tf_list = [handleline(x) for x in TCPFLAGS]
    _tf_keys = [x[0] for x in _tf_list]
    _tf_dict = dict(_tf_list)    
    for x in _tf_keys:
        if x==1:continue
        if x==128:continue
        for i in range(1, x):
            _tf_dict.update({x+i : _tf_dict[i] + '-' + _tf_dict[x]})
    return _tf_dict
 
def write_file():
    _tf_dict = gen_tcpflag_dict()
    try:
        f = open('tcpflag_desc.txt', 'w')
        _keys = _tf_dict.keys()
        for _k in _tf_dict.keys():    
            _line = '%s,%s\n'%(_k, _tf_dict[_k])
            f.write(_line)
    except Exception, e:
        import traceback
        traceback.print_exc()
    finally:
        f.close()
    
if __name__ == '__main__':
    #print generate()
    write_file()