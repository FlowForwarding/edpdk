 # Copyright (c) 2013 Tieto Global Oy
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 #     http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License. 


import os

from subprocess import Popen, PIPE

ERROR = -1

class Utils(object):

  def __init__(self):
    pass

  @staticmethod
  def execute(cmd=None, wait=True):
    if not cmd:
      return ERROR

    proc = Popen(cmd, shell=True)
    if wait:
      proc.wait()
  
    return proc.returncode

  @staticmethod
  def executeo(cmd=None, wait=True):
    if not cmd:
      return ERROR

    result = dict()
    proc = Popen(cmd, shell=True, stdout=PIPE)
    if wait:
      proc.wait()

    if proc.returncode == 0:
      result["stdout"] = proc.communicate()[0]
      result["proc"] = proc

    return result

  @staticmethod
  def kill_proc(searchstr=None):
    if not searchstr:
      return ERROR

    cmd = 'ps ax | grep "%s"' % searchstr    
    result = Utils.executeo(cmd)
    out = result["stdout"]
    cols = out.split(" ")

    rc = -1
    for c in cols:
      if len(c) > 0:
        cmd = "sudo kill -9 %s" % c
        rc = Utils.execute(cmd)
        break

    return rc        

class Test(object):
  
  def __init__(self, name=None):
    if not name:
       return ERROR
    self._name = name

  def run(self):
    print "Nothing to do"
    return 0

  def get_name(self):
    return self._name

class ContinuousIntegration(object):
  
  def __init__(self, tests=None):
    self._tests = tests    
    self._success = list()
    self._fails = list()
  
  def run_tests(self):
    print "Runnning tests..."
    for t in self._tests:
      print "\n===%s===" % t.get_name()
      ret = t.run()
      if ret == 0:        
        self._success.append(t.get_name())
      else:
        self._fails.append(t.get_name())

    self.display_results()

  def display_results(self):
     print "Success: %s" % len(self._success)
     for s in self._success:
       print ' ' + s

     print "Fails: %s" % len(self._fails)
     for f in self._fails:
       print ' ' + f
     
