# vim: ts=4:sw=4:expandtab

# BleachBit
# Copyright (C) 2008-2018 Andrew Ziem
# https://www.bleachbit.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""
Check for updates via the Internet
"""
#모듈
from __future__ import absolute_import, print_function

import bleachbit
from bleachbit import _

import hashlib
import logging
import os
import os.path
import platform
import socket
import sys
if sys.version >= (3, 0):
    from urllib.request import build_opener
    from urllib.error import URLError
else:
    from urllib2 import build_opener, URLError

import xml.dom.minidom

logger = logging.getLogger(__name__)

#최신 winapp2.ini 파일을 다운로드하는 함수 
def update_winapp2(url, hash_expected, append_text, cb_success):
    """Download latest winapp2.ini file.  Hash is sha512 or None to disable checks"""
    # first, determine whether an update is necessary
    #먼저 업데이트가 필요한지 여부를 확인합니다.
    #bleachbit모듈에서 personal_cleaners_dir을 가져온다.
    from bleachbit import personal_cleaners_dir
    #fn은 personal_cleaners_dir의 'winapp2.ini'이다.
    fn = os.path.join(personal_cleaners_dir, 'winapp2.ini')
    delete_current = False
    if os.path.exists(fn):
        #파일을 읽기모드로 연다.
        f = open(fn, 'r')
        hash_current = hashlib.sha512(f.read()).hexdigest()
        if not hash_expected or hash_current == hash_expected:
            # update is same as current
            #업데이트가 현재 업데이트와 동일하면 return한다.
            return
        #파일을 닫는다.
        f.close()
        delete_current = True
    # download update
    # 업데이트를 다운로드한다.
    opener = build_opener()
    opener.addheaders = [('User-Agent', user_agent())]
    doc = opener.open(fullurl=url, timeout=20).read()
    # verify hash
    #해시를 확인한다.
    hash_actual = hashlib.sha512(doc).hexdigest()
    #hash_expected이고 hash_actual이 아니면 hash_expected이다.
    if hash_expected and not hash_actual == hash_expected:
        raise RuntimeError("hash for %s actually %s instead of %s" %
                           (url, hash_actual, hash_expected))
    # delete current
    # current를 삭제한다.
    if delete_current:
        from bleachbit.FileUtilities import delete
        delete(fn, True)
    # write file
    # 파일을 쓰기모드로 열고 'New winapp2.ini was downloaded.'에 추가한다.
    if not os.path.exists(personal_cleaners_dir):
        os.mkdir(personal_cleaners_dir)
    f = open(fn, 'w')
    f.write(doc)
    append_text(_('New winapp2.ini was downloaded.'))
    cb_success()

#사용자 에이전트 문자열 반환하는 함수 
def user_agent():
    """Return the user agent string"""
    # __platform이 리눅스 혹은 윈도우이면 __os는 platform.uname()[2]이다.
    __platform = platform.system()  # Linux or Windows
    __os = platform.uname()[2]  # e.g., 2.6.28-12-generic or XP
     # sys.platform이 "win32"이면  __os = platform.uname()[3][0:3]이다.
    if sys.platform == "win32":
        # misleading: Python 2.5.4 shows uname()[2] as Vista on Windows 7
        __os = platform.uname()[3][
            0:3]  # 5.1 = Windows XP, 6.0 = Vista, 6.1 = 7
    elif sys.platform.startswith('linux'):
        dist = platform.dist()
        # example: ('fedora', '11', 'Leonidas')
        # example: ('', '', '') for Arch Linux
        if 0 < len(dist[0]):
            __os = dist[0] + '/' + dist[1] + '-' + dist[2]
    elif sys.platform[:6] == 'netbsd':
        __sys = platform.system()
        mach = platform.machine()
        rel = platform.release()
        __os = __sys + '/' + mach + ' ' + rel
    __locale = ""
    try:
        import locale
        __locale = locale.getdefaultlocale()[0]  # e.g., en_US
    except:
        logger.exception('Exception when getting default locale')

    try:
        import gtk
        gtkver = '; GTK %s' % '.'.join([str(x) for x in gtk.gtk_version])
    except:
        gtkver = ""

    agent = "BleachBit/%s (%s; %s; %s%s)" % (bleachbit.APP_VERSION,
                                             __platform, __os, __locale, gtkver)
    return agent

#업데이트에 버전 번호와 URL이 포함하는 함수.
def update_dialog(parent, updates):
    """Updates contains the version numbers and URLs"""
    #모듈
    import gtk
    from bleachbit.GuiBasic import open_url
    dlg = gtk.Dialog(title=_("Update BleachBit"),
                     parent=parent,
                     flags=gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT)
    dlg.set_default_size(250, 125)

    #label에 "A new version is available."을 띄운다.
    label = gtk.Label(_("A new version is available."))
    dlg.vbox.pack_start(label)

    #버전은 update[0], url은 update[1]에 초기화한다.
    for update in updates:
        ver = update[0]
        url = update[1]
        box_update = gtk.HBox()
        # TRANSLATORS: %s expands to version such as '0.8.4' or '0.8.5beta' or
        # similar
        button_stable = gtk.Button(_("Update to version %s") % ver)
        button_stable.connect(
            'clicked', lambda dummy: open_url(url, parent, False))
        button_stable.connect('clicked', lambda dummy: dlg.response(0))
        box_update.pack_start(button_stable, False, padding=10)
        dlg.vbox.pack_start(box_update, False)

     #버튼을 추가한다.
    dlg.add_button(gtk.STOCK_CLOSE, gtk.RESPONSE_CLOSE)

    #화면에 뛰우고 작동시킨다.
    dlg.show_all()
    dlg.run()
    dlg.destroy()

    return False

#인터넷을 통해 업데이트 확인하는 함수 
def check_updates(check_beta, check_winapp2, append_text, cb_success):
    """Check for updates via the Internet"""
    #opner초기화
    opener = build_opener()
    socket.setdefaulttimeout(bleachbit.socket_timeout)
    opener.addheaders = [('User-Agent', user_agent())]
    try:
        #bleachbit.update_check_url을 연다.
        handle = opener.open(bleachbit.update_check_url)
    except URLError:
        #오류창을 띄운다.
        logger.exception(
            _('Error when opening a network connection to %s to check for updates. Please verify the network is working.' %
                bleachbit.update_check_url))
        return ()
    #doc초기화.
    doc = handle.read()
    try:
        #dom을 xml파일로 초기화.
        dom = xml.dom.minidom.parseString(doc)
    except:
        #오류창을 띄운다.
        logger.exception('The update information does not parse: %s', doc)
        return ()
    #element에 버전과 url을 저장하는 함수 
    def parse_updates(element):
        if element:
            ver = element[0].getAttribute('ver')
            url = element[0].firstChild.data
            return ver, url
        return ()

    stable = parse_updates(dom.getElementsByTagName("stable"))
    beta = parse_updates(dom.getElementsByTagName("beta"))

    wa_element = dom.getElementsByTagName('winapp2')
    if check_winapp2 and wa_element:
        wa_sha512 = wa_element[0].getAttribute('sha512')
        wa_url = wa_element[0].getAttribute('url')
        update_winapp2(wa_url, wa_sha512, append_text, cb_success)

    dom.unlink()

    if stable and beta and check_beta:
        return stable, beta
    if stable:
        return stable,
    if beta and check_beta:
        return beta,
    return ()
