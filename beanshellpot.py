from flask import Flask, render_template, make_response, request
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource
from twisted.web.server import Site
from twisted.python import logfile
import datetime, time, re, json, os


# 在twisted中，flask本体是app
app = Flask(__name__)

raw_pre1 = '''
<table width="80%" cellpadding="6" border="1"><tbody><tr><td bgcolor="#eeeeee">
<pre>'''
raw_pre2 = '''</pre>
</td></tr></tbody></table>
'''
raw_id = '''
<table width="80%" cellpadding="6" border="1"><tbody><tr><td bgcolor="#eeeeee">
<pre>uid=0(root) gid=0(root) group=0(root)

</pre>
</td></tr></tbody></table>
'''
raw_ifconfig = '''
<table width="80%" cellpadding="6" border="1"><tbody><tr><td bgcolor="#eeeeee">
<pre>
eth0: flags=4163 UP,BROADCAST,RUNNING,MULTICAST  mtu 1500
        inet 10.0.4.2  netmask 255.255.252.0  broadcast 10.0.7.255
        inet6 fe80::5054:ff:fef7:3b94  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:f7:3b:94  txqueuelen 1000  (Ethernet)
        RX packets 1865293500  bytes 219358215209 (204.2 GiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1926495678  bytes 265904236788 (247.6 GiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73 UP,LOOPBACK,RUNNING   mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 985200  bytes 587500708 (560.2 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 985200  bytes 587500708 (560.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
</pre>
</td></tr></tbody></table>
'''



@app.route("/index.jsp")
def index():
    resp = make_response((render_template("nc.html")))
    resp.headers["Set-Cookie"] = "JSESSIONID=3462A7D92A5C420A3651B644FED34549.server"
    return resp


@app.route("/servlet/~ic/bsh.servlet.BshServlet/", methods=['GET', 'POST'])
def servlet():
    potserver = make_response((render_template("pot.html", textarea="print(\"hello!\");")))
    potserver.headers["Set-Cookie"] = "JSESSIONID=3462A7D92A5C420A3651B644FED34549.server"

    # 处理form表单
    if request.method == 'POST':
        # 如果是form表单的请求体，那么则可以使用request.form来获取参数。
        requestbody = request.form
        result = formdo(requestbody)
        return result
    else:
        return potserver


@app.route("/favicon")
def burpload():
    dire = os.path.dirname('./log/')
    outfile = logfile.DailyLogFile("beanshellpot.log", dire, defaultMode=0o664)
    # print(session.get('burp'))
    data = {'timestamp': datetime.datetime.fromtimestamp(time.time()).isoformat(),
            'dst_ip': "127.0.0.1",
            'dst_port': 8081,
            'src_ip': request.remote_addr,
            'use_bp': True,
            }
    line = json.dumps(data)
    outfile.write(line + "\n")
    outfile.flush()


# 处理接收post请求的form表单参数
def formdo(requestbody):
    command = requestbody.get('bsh.script')
    # isouterror = requestbody.get('bsh.servlet.captureOutErr')
    israw = requestbody.get('bsh.servlet.output')
    # logmode
    hosts = request.remote_addr
    logmode(command, hosts)

    if israw == "raw":
        return rawresponse(command)
    else:
        return unrawresponse(command)


def unrawresponse(command):
    def_h2 = '''
        <h2>Script Output</h2>
        '''
    def_return = '''
        <h2>Script Return Value</h2>
        <pre>null
        </pre>
        <p></p>
        '''

    # 默认
    if re.match(r'print\("(.*)"\)(.)', command, re.M | re.I) or re.match(r'print\(\'(.*)\'\)(.)', command, re.M | re.I):
        matchobj = re.match(r'print\("(.*)"\)', command, re.M | re.I)
        # print(matchObj.group(1))
        raw_print = raw_pre1 + matchobj.group(1) + raw_pre2
        changedserver = make_response(
            (render_template("pot.html", changed_h2=def_h2, changed_table=raw_print, changed_return=def_return, textarea=command)))
        return changedserver

    # goby or id
    elif (command == 'exec(\'id\')') or ('id' in command):
        changedserver = make_response(
            (render_template("pot.html", changed_h2=def_h2, changed_table=raw_id, changed_return=def_return, textarea=command)))
        return changedserver

    # asdasdqkq1/yonyou-nc-exp or ifconfig
    elif (command == 'ex\u0065c("ifconfig");') or ('ifconfig' in command):
        changedserver = make_response(
            (render_template("pot.html", changed_h2=def_h2, changed_table=raw_ifconfig, changed_return=def_return, textarea=command)))
        return changedserver

    elif re.match(r'exec\("(.*)"\)(.)', command, re.M | re.I) or re.match(r'exec\(\'(.*)\'\)(.)', command, re.M | re.I):
        raw_print = raw_pre1+"Sourced file: inline evaluation of: ``"+command+" : target exception<hr>"+raw_pre2
        changedserver = make_response(
            (render_template("pot.html", changed_h2=def_h2, changed_table=raw_print, changed_return=def_return,
                             textarea=command)))
        return changedserver
    else:
        raw_print = raw_pre1 + raw_pre2
        changedserver = make_response(
            (render_template("pot.html", changed_h2=def_h2, changed_table=raw_print, changed_return=def_return,
                             textarea=command)))
        return changedserver

def rawresponse(command):
    if re.match(r'print\("(.*)"\)', command, re.M | re.I):
        matchobj = re.match(r'print\("(.*)"\)', command, re.M | re.I)
        return matchobj.group(1)

    # goby or id
    elif (command == 'exec(\'id\')') or ('id' in command):
        return "uid=0(root) gid=0(root) group=0(root)"

    # asdasdqkq1/yonyou-nc-exp or ifconfig
    elif (command == 'ex\u0065c("ifconfig");') or ('ifconfig' in command):
        return '''
        eth0: flags=4163UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.4.2  netmask 255.255.252.0  broadcast 10.0.7.255
        inet6 fe80::5054:ff:fef7:3b94  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:f7:3b:94  txqueuelen 1000  (Ethernet)
        RX packets 1865293500  bytes 219358215209 (204.2 GiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1926495678  bytes 265904236788 (247.6 GiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 985200  bytes 587500708 (560.2 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 985200  bytes 587500708 (560.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
        </pre>
        '''


def logmode(command, hosts):
    dire = os.path.dirname('./log/')
    outfile = logfile.DailyLogFile("beanshellpot.log", dire, defaultMode=0o664)
    # print(session.get('burp'))
    data = {'timestamp': datetime.datetime.fromtimestamp(time.time()).isoformat(),
            'dst_ip': "127.0.0.1",
            'dst_port': 8081,
            'src_ip': hosts,
            'command': command,
            }

    line = json.dumps(data)
    outfile.write(line + "\n")
    outfile.flush()


if __name__ == '__main__':
    resource = WSGIResource(reactor, reactor.getThreadPool(), app)
    site = Site(resource)
    reactor.listenTCP(8081, site)
    reactor.run()
