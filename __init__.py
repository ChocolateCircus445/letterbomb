import os, zipfile, StringIO, hashlib, hmac, struct, logging, urllib, random, json
from datetime import datetime, timedelta
TEMPLATES = {
    'U':"templateU.bin",
    'E':"templateE.bin",
    'J':"templateJ.bin",
    'K':"templateK.bin",
}

LBPATH = os.path.abspath(os.path.join(os.path.realpath(__file__), os.pardir))

BUNDLEBASE = os.path.join(LBPATH, 'bundle')


def haxx_offline(region, mac_raw, bundle_hackmii, outfile):
    # region can be 'E', 'J', 'K', or 'U'
    # mac_raw is the mac address split by hyphens.
    # ex. 00-24-ff-ff-ff-ff
    # bundle_hackmii is a Boolean that determines whether or not to bundle the bundle folder
    # outfile is a path where the output should go. Must include the filename.
    OUI_LIST = [i.decode('hex') for i in open(os.path.join(LBPATH, 'oui_list.txt')).read().split("\n") if len(i)==6]
    dt = datetime.utcnow() - timedelta(1)
    delta = (dt - datetime(2000, 1, 1))
    timestamp = delta.days * 86400 + delta.seconds
    template = TEMPLATES[region]
    mac_list = mac_raw.split("-")
    mac = ""
    bundle = bundle_hackmii
    for i in mac_list:
        mac += chr(int(i, 16))
    if mac == "\x00\x17\xab\x99\x99\x99":
        raise Exception('Derp MAC %s at %d ver %s bundle %r', mac.encode('hex'), timestamp, region, bundle)
        return "If you're using Dolphin, try File->Open instead ;-)."

    if not any([mac.startswith(i) for i in OUI_LIST]):
        raise Exception('Bad MAC %s at %d ver %s bundle %r', mac.encode('hex'), timestamp, request.form['region'], bundle)
        return "The exploit will only work if you enter your Wii's MAC address."


    key = hashlib.sha1(mac+"\x75\x79\x79").digest()

    blob = bytearray(open(os.path.join(LBPATH, template),'rb').read())
    blob[0x08:0x10] = key[:8]
    blob[0xb0:0xc4] = "\x00"*20
    blob[0x7c:0x80] = struct.pack(">I", timestamp)
    blob[0x80:0x8a] = "%010d"%timestamp
    blob[0xb0:0xc4] = hmac.new(key[8:], str(blob), hashlib.sha1).digest()

    path = "private/wii/title/HAEA/%s/%s/%04d/%02d/%02d/%02d/%02d/HABA_#1/txt/%08X.000" % (
        key[:4].encode('hex').upper(), key[4:8].encode('hex').upper(),
        dt.year, dt.month-1, dt.day, dt.hour, dt.minute, timestamp
    )

    zipdata = StringIO.StringIO()
    zip = zipfile.ZipFile(zipdata, 'w')
    zip.writestr(path, str(blob))
    BUNDLE = [(name, os.path.join(BUNDLEBASE,name)) for name in os.listdir(BUNDLEBASE) if not name.startswith(".")]
    if bundle:
        for name, path in BUNDLE:
            zip.write(path, name)
    zip.close()
    open(os.path.join(outfile), "wb").write(zipdata.getvalue())
    zipdata.close()
