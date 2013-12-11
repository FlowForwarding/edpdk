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


#!/usr/bin/python

import signal

import tu

class BuildTest(tu.Test):
  """
    Test the build
  """
  def __init__(self):
    tu.Test.__init__(self, "Build Test")

  def run(self):
    cmd = "make -C ../ clean && make -C ../"
    rc = tu.Utils.execute(cmd)
    return rc

class InstallTest(tu.Test):
  """
    Test the installation
  """
  def __init__(self):
    tu.Test.__init__(self, "Install Test")
   
  def run(self):
    cmd = "make -C ../ install"
    rc = tu.Utils.execute(cmd)
    return rc

class MinimalEdpdkRun(tu.Test):
  """ 
    Test minimal edpdk run.  It must have at least
    2 cores and ports to allow forwarding
  """
  def __init__(self):
    tu.Test.__init__(self, "Minimal Edpdk Run")

  def run(self): 
    cmd = "sudo ../bin/edpdk -c 0x3 -n 4 -- --rx=0:0:1 --tx=0:0:1"
    rc = tu.Utils.execute(cmd, False)
    if cmd:
      cmd = 'ps ax | grep "sudo ../bin/edpdk -c 0x3 -n 4 -- --rx=0:0:1 --tx=0:0:1" > /dev/null'
      rc = tu.Utils.execute(cmd)
    return rc


class MissingOptionTopo(tu.Test):
  """
    Test error-handling when topo
    option is missing
  """ 
  def __init__(self):
    tu.Test.__init__(self, "Missing --topo")

  def run(self):
    cmd = "sudo ../bin/edpdk -c 0x3 -n 4"
    rc = tu.Utils.execute(cmd)
    if rc != 0:
      return 0
    return -1


class BadOptionTopo(tu.Test):
  """
    Test error-handling when topo option
    is incorrectly used
  """
  def __init__(self):
    tu.Test.__init__(self, "Bad --topo")

  def run(self):
    cmd = "sudo ../bin/edpdk -c 0x3 -n 4 -- --topo"
    rc = tu.Utils.execute(cmd)
    if rc != 0:
      return 0
    return -1


def main():

  """
    Create tests and run
  """
  tests = list()
  tests.append(BuildTest())
  tests.append(InstallTest())
  tests.append(MissingOptionTopo())
  tests.append(MinimalEdpdkRun())
  tests.append(BadOptionTopo())

  ci = tu.ContinuousIntegration(tests)
  ci.run_tests()

if __name__ == '__main__':
  main()

