#   BSD LICENSE
# 
#   Copyright(c) 2013 Tieto Global Oy. All rights reserved.
#   All rights reserved.
# 
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
# 
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
# 
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


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
     
