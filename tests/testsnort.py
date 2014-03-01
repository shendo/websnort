from datetime import datetime
from websnort import snort

def test_parse_alert():
    count = 0
    for x in snort.parse_alert("01/28/14-22:26:04.885446 [**] [1:1917:11] INDICATOR-SCAN UPnP service discover attempt [**] [Classification: Detection of a Network Scan] [Priority: 3] {UDP} 10.1.1.132:58650 -> 239.255.255.250:1900\n"):
        assert x['message'] == "INDICATOR-SCAN UPnP service discover attempt"
        assert x['timestamp'] == datetime(2014, 01, 28, 22, 26, 04, 885446)
        assert x['classtype'] == "Detection of a Network Scan"
        assert x['sid'] == 1917
        assert x['revision'] == 11
        assert x['protocol'] == 'UDP'
        assert x['source'] == "10.1.1.132:58650"
        assert x['destination'] == "239.255.255.250:1900"
        count += 1
    assert count == 1
       
       
if __name__ == '__main__':
    test_parse_alert() 