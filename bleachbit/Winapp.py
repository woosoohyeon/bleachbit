
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
Import Winapp2.ini files
"""

from __future__ import absolute_import, print_function

import logging
import os
import glob
import re
from xml.dom.minidom import parseString

import bleachbit
from bleachbit import Cleaner, Windows
from bleachbit.Action import Delete, Winreg
from bleachbit import _, FSE, expandvars

logger = logging.getLogger(__name__)


# TRANSLATORS: This is cleaner name for cleaners imported from winapp2.ini
# TRANSLATORs: 이것은 winapp2.ini에서 가져온 클리너를 위한 더 깨끗한 이름입니다.
langsecref_map = {'3021': ('winapp2_applications', _('Applications')),
                  # TRANSLATORS: This is cleaner name for cleaners imported
                  # from winapp2.ini
                  '3022': ('winapp2_internet', _('Internet')),
                  # TRANSLATORS: This is cleaner name for cleaners imported
                  # from winapp2.ini
                  '3023': ('winapp2_multimedia', _('Multimedia')),
                  # TRANSLATORS: This is cleaner name for cleaners imported
                  # from winapp2.ini
                  '3024': ('winapp2_utilities', _('Utilities')),
                  # TRANSLATORS: This is cleaner name for cleaners imported
                  # from winapp2.ini.
                  '3025': ('winapp2_windows', 'Microsoft Windows'),
                  '3026': ('winapp2_mozilla', 'Firefox/Mozilla'),
                  '3027': ('winapp2_opera', 'Opera'),
                  '3028': ('winapp2_safari', 'Safari'),
                  '3029': ('winapp2_google_chrome', 'Google Chrome'),
                  '3030': ('winapp2_thunderbird', 'Thunderbird'),
                  '3031': ('winapp2_windows_store', 'Windows Store'),
                  # Section=Games (technically not langsecref)
                  'Games': ('winapp2_games', _('Games'))}

#XML 엔티티를 가벼운 방식으로 제거하는 함수
def xml_escape(s):
    """Lightweight way to escape XML entities"""
    return s.replace('&', '&amp;').replace('"', '&quot;')

#섹션 이름을 적절한 옵션 이름으로 표준화하는 함수
def section2option(s):
    """Normalize section name to appropriate option name"""
    ret = re.sub(r'[^a-z0-9]', '_', s.lower())
    ret = re.sub(r'_+', '_', ret)
    ret = re.sub(r'(^_|_$)', '', ret)
    return ret

#탐지기가 와 호환되는지의 여부와 현재 운영 체제 또는 제공된 모의 버전을 사용하는지 판단하는 함수
def detectos(required_ver, mock=False):
    """Returns boolean whether the detectos is compatible with the
    current operating system, or the mock version, if given."""
    # Do not compare as string because Windows 10 (build 10.0) comes after
    # Windows 8.1 (build 6.3)
    assert isinstance(required_ver, (str, unicode))
    #현재의 os를 초기화 한다.
    current_os = (mock if mock else Windows.parse_windows_build())
    #required_ver에 required_ver을 붙인다.
    required_ver = required_ver.strip()
    #만약 '|'가 required_ver라면 
    if '|' in required_ver:
        # Format of min|max
        # req_min에 required_ver[0]에 '|'붙인 것을 초기화한다.
        req_min = required_ver.split('|')[0]
        # req_max에 required_ver[1]에 '|'붙인 것을 초기화한다.
        req_max = required_ver.split('|')[1]
        
        #비교를 통해 false와 true을 리턴한다.
        if req_min and current_os < Windows.parse_windows_build(req_min):
            return False
        if req_max and current_os > Windows.parse_windows_build(req_max):
            return False
        return True
    else:
        #버전이 호환된다면 현재의 os를 반환한다.
        # Exact version
        return Windows.parse_windows_build(required_ver) == current_os

#특수 Winapp2.ini 규칙을 사용하여 환경 변수 확장하는 함수 
def winapp_expand_vars(pathname):
    """Expand environment variables using special Winapp2.ini rules"""
    # This is the regular expansion
    # expand1변수 초기화 
    expand1 = expandvars(pathname)
    # Winapp2.ini expands %ProgramFiles% to %ProgramW6432%, etc.
    #subs초기화 
    subs = (('ProgramFiles', 'ProgramW6432'),
            ('CommonProgramFiles', 'CommonProgramW6432'))
    
    #subs길이만큼 반복 
    for (sub_orig, sub_repl) in subs:
        pattern = re.compile('%{}%'.format(sub_orig), flags=re.IGNORECASE)
        #pattern이 pathname와 같다면 
        if pattern.match(pathname):
            #expand2초기화 
            expand2 = pattern.sub('%{}%'.format(sub_repl), pathname)
            #expand1, expandvars반환
            return expand1, expandvars(expand2)
     #반환 
    return expand1,

#DetectFile#=에 대한 경로가 있는지 확인하느 함수 
def detect_file(pathname):
    """Check whether a path exists for DetectFile#="""
    for expanded in winapp_expand_vars(pathname):
        for _ in glob.iglob(expanded):
            return True
    return False

#SpecialDetect= 소프트웨어가 존재하는지 확인하는 함수 
def special_detect(code):
    """Check whether the SpecialDetect== software exists"""
    # The last two are used only for testing
    sd_keys = {'DET_CHROME': r'HKCU\Software\Google\Chrome',
               'DET_MOZILLA': r'HKCU\Software\Mozilla\Firefox',
               'DET_OPERA': r'HKCU\Software\Opera Software',
               'DET_THUNDERBIRD': r'HKLM\SOFTWARE\Clients\Mail\Mozilla Thunderbird',
               'DET_WINDOWS': r'HKCU\Software\Microsoft',
               'DET_SPACE_QUEST': r'HKCU\Software\Sierra Games\Space Quest'}
    if sd_keys.has_key(code):
        return Windows.detect_registry_key(sd_keys[code])
    else:
        logger.error('Unknown SpecialDetect=%s', code)
    return False

#끝이 없는 원본과 동일한지 판단하는 함수
def fnmatch_translate(pattern):
    """Same as the original without the end"""
    import fnmatch
    ret = fnmatch.translate(pattern)
    if ret.endswith('$'):
        return ret[:-1]
    if ret.endswith(r'\Z(?ms)'):
        return ret[:-7]
    return ret

#Winapp2.ini 스타일 파일에서 클리너 생성하는 클래스 
class Winapp:

    """Create cleaners from a Winapp2.ini-style file"""
    
    #Winapp2.ini 스타일 파일에서 클리너 생성하는 함수
    def __init__(self, pathname):
        """Create cleaners from a Winapp2.ini-style file"""

        self.cleaners = {}
        self.cleaner_ids = []
        for langsecref in set(langsecref_map.values()):
            self.add_section(langsecref[0], langsecref[1])
        self.errors = 0
        self.parser = bleachbit.RawConfigParser()
        self.parser.read(pathname)
        self.re_detect = re.compile(r'^detect(\d+)?$')
        self.re_detectfile = re.compile(r'^detectfile(\d+)?$')
        self.re_excludekey = re.compile(r'^excludekey\d+$')
        for section in self.parser.sections():
            try:
                self.handle_section(section)
            except Exception:
                self.errors += 1
                logger.exception('parsing error in section %s', section)
    
    #섹션 추가(클리너)함수 
    def add_section(self, cleaner_id, name):
        """Add a section (cleaners)"""
        self.cleaner_ids.append(cleaner_id)
        self.cleaners[cleaner_id] = Cleaner.Cleaner()
        self.cleaners[cleaner_id].id = cleaner_id
        self.cleaners[cleaner_id].name = name
        self.cleaners[cleaner_id].description = _('Imported from winapp2.ini')
        # The detect() function in this module effectively does what
        # auto_hide() does, so this avoids redundant, slow processing.
        self.cleaners[cleaner_id].auto_hide = lambda: False
        
    #Langsecref(또는 섹션 이름)가 있으면 내부 BleachBit 클리너 ID를 찾는 함수
    def section_to_cleanerid(self, langsecref):
        """Given a langsecref (or section name), find the internal
        BleachBit cleaner ID."""
        # pre-defined, such as 3021
        if langsecref in langsecref_map.keys():
            return langsecref_map[langsecref][0]
        # custom, such as games
        cleanerid = 'winapp2_' + section2option(langsecref)
        if cleanerid not in self.cleaners:
            # never seen before
            self.add_section(cleanerid, langsecref)
        return cleanerid
      
      
    #하나의 제외키를 클리너ML nwholeregex로 변환하는 함수
    def excludekey_to_nwholeregex(self, excludekey):
        r"""Translate one ExcludeKey to CleanerML nwholeregex

        Supported examples
        FILE=%LocalAppData%\BleachBit\BleachBit.ini
        FILE=%LocalAppData%\BleachBit\|BleachBit.ini
        FILE=%LocalAppData%\BleachBit\|*.ini
        FILE=%LocalAppData%\BleachBit\|*.ini;*.bak
        PATH=%LocalAppData%\BleachBit\
        PATH=%LocalAppData%\BleachBit\|*.*
        """
        parts = excludekey.split('|')
        parts[0] = parts[0].upper()
        if parts[0] == 'REG':
            raise NotImplementedError('REG not supported in ExcludeKey')
            
        #마지막 부분에 파일 이름이 있다.
        # the last part contains the filename(s)
        files = None
        files_regex = ''
        if len(parts) == 3:
            files = parts[2].split(';')
            if len(files) == 1:
                ## *.* 또는 *.log와 같은 하나의 파일 패턴
                # one file pattern like *.* or *.log
                files_regex = fnmatch_translate(files[0])
                if files_regex == '*.*':
                    files = None
            elif len(files) > 1:
              # *.log.*bak와 같은 여러 개의 파일 패턴
                # multiple file patterns like *.log;*.bak
                files_regex = '(%s)' % '|'.join(
                    [fnmatch_translate(f) for f in files])
        # 중간 부분에 파일이 있다.
        # the middle part contains the file
        regexes = []
        for expanded in winapp_expand_vars(parts[1]):
            regex = None
            if not files:
                #세 번째 부분은 없으므로 폴더이거나 파일이 직접 지정되기도 함.
                # There is no third part, so this is either just a folder,
                # or sometimes the file is specified directly.
                regex = fnmatch_translate(expanded)
            if files:
                # 이 트리 또는 하위 폴더에 있는 하나 이상의 파일 형식과 일치
                # match one or more file types, directly in this tree or in any
                # sub folder
                regex = '%s.*%s' % (
                    fnmatch_translate(expanded), files_regex)
            regexes.append(regex)

        if len(regexes) == 1:
            return regexes[0]
        else:
            return '(%s)' % '|'.join(regexes)
    #섹션을 표시할지 여부 확인하는 함수 
    def detect(self, section):
        """Check whether to show the section

        The logic:
        If the DetectOS does not match, the section is inactive.
        If any Detect or DetectFile matches, the section is active.
        If neither Detect or DetectFile was given, the section is active.
        Otherwise, the section is inactive.
        """
        if self.parser.has_option(section, 'detectos'):
            required_ver = self.parser.get(section, 'detectos').decode(FSE)
            if not detectos(required_ver):
                return False
        any_detect_option = False
        if self.parser.has_option(section, 'specialdetect'):
            any_detect_option = True
            sd_code = self.parser.get(section, 'specialdetect')
            if special_detect(sd_code):
                return True
        for option in self.parser.options(section):
            if re.match(self.re_detect, option):
                # Detect= checks for a registry key
                any_detect_option = True
                key = self.parser.get(section, option).decode(FSE)
                if Windows.detect_registry_key(key):
                    return True
            elif re.match(self.re_detectfile, option):
                # DetectFile= checks for a file
                any_detect_option = True
                key = self.parser.get(section, option).decode(FSE)
                if detect_file(key):
                    return True
        return not any_detect_option

     #섹션을 다루는 함수 
    def handle_section(self, section):
        """Parse a section"""
        #섹션이 활성화되었는지 확인한다.
        # check whether the section is active (i.e., whether it will be shown)
        if not self.detect(section):
            return
        # 제외키는 파일, 경로 또는 레지스트리 키를 무시.
        # excludekeys ignores a file, path, or registry key
        excludekeys = []
        for option in self.parser.options(section):
            if re.match(self.re_excludekey, option):
                excludekeys.append(
                    self.excludekey_to_nwholeregex(self.parser.get(section, option).decode(FSE)))
        # there are two ways to specify sections: langsecref= and section=
        if self.parser.has_option(section, 'langsecref'):
            #Langsecref 번호가 알려져 있는지 확인합니다.
            # verify the langsecref number is known
            # langsecref_num is 3021, games, etc.
            langsecref_num = self.parser.get(section, 'langsecref').decode(FSE)
        elif self.parser.has_option(section, 'section'):
            langsecref_num = self.parser.get(section, 'section').decode(FSE)
        else:
            logger.error(
                'neither option LangSecRef nor Section found in section %s', section)
            return
        #BleachBit 내부 클리너 ID를 찾는다.
        # find the BleachBit internal cleaner ID
        lid = self.section_to_cleanerid(langsecref_num)
        self.cleaners[lid].add_option(
            section2option(section), section.replace('*', ''), '')
        for option in self.parser.options(section):
            if option.startswith('filekey'):
                self.handle_filekey(lid, section, option, excludekeys)
            elif option.startswith('regkey'):
                self.handle_regkey(lid, section, option)
            elif option == 'warning':
                self.cleaners[lid].set_warning(
                    section2option(section), self.parser.get(section, 'warning').decode(FSE))
            elif option in ('default', 'langsecref', 'section', 'detectos', 'specialdetect') \
                    or re.match(self.re_detect, option) \
                    or re.match(self.re_detectfile, option) \
                    or re.match(self.re_excludekey, option):
                pass
            else:
                logger.warning(
                    'unknown option %s in section %s', option, section)
                return
    #구문 분석된 파일 키를 작업 공급자로 변경하는 함수 
    def __make_file_provider(self, dirname, filename, recurse, removeself, excludekeys):
        """Change parsed FileKey to action provider"""
        #조건문을 통해 원하는 파일명을 찾는다.
        regex = ''
        if recurse:
            search = 'walk.files'
            path = dirname
            if filename.startswith('*.'):
                filename = filename.replace('*.', '.')
            if filename == '.*':
                if removeself:
                    search = 'walk.all'
            else:
                import fnmatch
                regex = ' regex="%s" ' % (fnmatch.translate(filename))
        else:
            search = 'glob'
            path = os.path.join(dirname, filename)
            if path.find('*') == -1:
                search = 'file'
        excludekeysxml = ''
        if excludekeys:
          #key의 길이가 1보다 크다면 
            if len(excludekeys) > 1:
                # multiple
                exclude_str = '(%s)' % '|'.join(excludekeys)
            else:
              #키의 일이가 하나라면 
                # just one
                exclude_str = excludekeys[0]
            excludekeysxml = 'nwholeregex="%s"' % xml_escape(exclude_str)
        action_str = u'<option command="delete" search="%s" path="%s" %s %s/>' % \
                     (search, xml_escape(path), regex, excludekeysxml)
        #삭제한다.
        yield Delete(parseString(action_str).childNodes[0])
        if removeself:
            action_str = u'<option command="delete" search="file" path="%s"/>' % \
                         (xml_escape(dirname))
            yield Delete(parseString(action_str).childNodes[0])
    #FileKey# 옵션을 구문 분석하는 함수 
    def handle_filekey(self, lid, ini_section, ini_option, excludekeys):
        """Parse a FileKey# option.
        #섹션이 [응용 프로그램 이름]이고 옵션이 FileKey#이다.
        Section is [Application Name] and option is the FileKey#"""
        elements = self.parser.get(
            ini_section, ini_option).decode(FSE).strip().split('|')
        dirnames = winapp_expand_vars(elements.pop(0))
        filenames = ""
        if elements:
            filenames = elements.pop(0)
        recurse = False
        removeself = False
        for element in elements:
            element = element.upper()
            if element == 'RECURSE':
                recurse = True
            elif element == 'REMOVESELF':
                recurse = True
                removeself = True
            else:
                logger.warning(
                    'unknown file option %s in section %s', element, ini_section)
        for filename in filenames.split(';'):
            for dirname in dirnames:
                for provider in self.__make_file_provider(dirname, filename, recurse, removeself, excludekeys):
                    self.cleaners[lid].add_action(
                        section2option(ini_section), provider)
    #RegKey# 옵션을 구문 분석하는 함수
    def handle_regkey(self, lid, ini_section, ini_option):
        """Parse a RegKey# option"""
        elements = self.parser.get(
            ini_section, ini_option).decode(FSE).strip().split('|')
        path = xml_escape(elements[0])
        name = ""
        if len(elements) == 2:
            name = 'name="%s"' % xml_escape(elements[1])
        action_str = '<option command="winreg" path="%s" %s/>' % (path, name)
        provider = Winreg(parseString(action_str).childNodes[0])
        self.cleaners[lid].add_action(section2option(ini_section), provider)
        
    #생성된 클리너를 반환하는 함수 
    def get_cleaners(self):
        """Return the created cleaners"""
        for cleaner_id in self.cleaner_ids:
            if self.cleaners[cleaner_id].is_usable():
                yield self.cleaners[cleaner_id]

#winapp2.ini 파일 나열하는 함수
def list_winapp_files():
    """List winapp2.ini files"""
    for dirname in (bleachbit.personal_cleaners_dir, bleachbit.system_cleaners_dir):
        fname = os.path.join(dirname, 'winapp2.ini')
        if os.path.exists(fname):
            yield fname

#winapp2.ini 파일 검색 및 로드하는 함수 
def load_cleaners():
    """Scan for winapp2.ini files and load them"""
    for pathname in list_winapp_files():
        try:
            inicleaner = Winapp(pathname)
        except Exception as e:
            logger.exception(
                "Error reading winapp2.ini cleaner '%s'", pathname)
        else:
            for cleaner in inicleaner.get_cleaners():
                Cleaner.backends[cleaner.id] = cleaner
