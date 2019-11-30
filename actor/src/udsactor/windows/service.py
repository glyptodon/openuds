# -*- coding: utf-8 -*-
#
# Copyright (c) 2014 Virtual Cable S.L.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#    * Neither the name of Virtual Cable S.L. nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''
@author: Adolfo Gómez, dkmaster at dkmon dot com
'''
# pylint: disable=invalid-name
import struct
import subprocess
import os
import stat
import typing

import win32serviceutil
import win32service
import win32security
import win32net
import win32event
import win32com.client
import pythoncom
import servicemanager

from . import operations
from . import store
from ..service import CommonService

from ..log import logger

from .SENS import SensLogon
from .SENS import logevent
from .SENS import SENSGUID_EVENTCLASS_LOGON
from .SENS import SENSGUID_PUBLISHER
from .SENS import PROGID_EventSubscription
from .SENS import PROGID_EventSystem

REMOTE_USERS_SID = 'S-1-5-32-555'  # Well nown sid for remote desktop users

class UDSActorSvc(win32serviceutil.ServiceFramework, CommonService):
    '''
    This class represents a Windows Service for managing actor interactions
    with UDS Broker and Machine
    '''
    # ServiceeFramework related
    _svc_name_ = "UDSActorNG"
    _svc_display_name_ = "UDS Actor Service"
    _svc_description_ = "UDS Actor Management Service"
    # 'System Event Notification' is the SENS service
    _svc_deps_ = ['EventLog', 'SENS']

    _user: typing.Optional[str]
    _hWaitStop: typing.Any

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        CommonService.__init__(self)

        self._hWaitStop = win32event.CreateEvent(None, 1, 0, None)
        self._user = None

    def SvcStop(self) -> None:
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._isAlive = False
        win32event.SetEvent(self.hWaitStop)

    SvcShutdown = SvcStop

    def notifyStop(self) -> None:
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STOPPED, (self._svc_name_, ''))

    def doWait(self, miliseconds: int) -> None:
        win32event.WaitForSingleObject(self.hWaitStop, miliseconds)

    def oneStepJoin(self, name: str, domain: str, ou: str, account: str, password: str) -> None:
        '''
        Ejecutes the join domain in exactly one step
        '''
        currName = operations.getComputerName()
        # If name is desired, simply execute multiStepJoin, because computer
        # name will not change
        if currName.lower() == name.lower():
            self.multiStepJoin(name, domain, ou, account, password)
            return

        operations.renameComputer(name)
        logger.debug('Computer renamed to {} without reboot'.format(name))
        operations.joinDomain(domain, ou, account, password, executeInOneStep=True)
        logger.debug('Requested join domain {} without errors'.format(domain))
        self.reboot()

    def multiStepJoin(self, name: str, domain: str, ou: str, account: str, password: str) -> None:
        currName = operations.getComputerName()
        if currName.lower() == name.lower():
            currDomain = operations.getDomainName()
            if currDomain:
                # logger.debug('Name: "{}" vs "{}", Domain: "{}" vs "{}"'.format(currName.lower(), name.lower(), currDomain.lower(), domain.lower()))
                logger.info('Machine {} is part of domain {}'.format(name, domain))
                self.setReady()
            else:
                operations.joinDomain(domain, ou, account, password, executeInOneStep=False)
                self.reboot()
        else:
            operations.renameComputer(name)
            logger.info('Rebooting computer got activate new name {}'.format(name))
            self.reboot()

    def joinDomain(  # pylint: disable=unused-argument, too-many-arguments
            self,
            name: str,
            domain: str,
            ou: str,
            account: str,
            password: str
        ) -> None:
        versionData = operations.getWindowsVersion()
        versionInt = versionData[0] * 10 + versionData[1]
        logger.debug('Starting joining domain {} with name {} (detected operating version: {})'.format(domain, name, versionData))
        # Accepts one step joinDomain, also remember XP is no more supported by
        # microsoft, but this also must works with it because will do a "multi
        # step" join
        if versionInt >= 60 and not store.useOldJoinSystem():
            self.oneStepJoin(name, domain, ou, account, password)
        else:
            logger.info('Using multiple step join because configuration requests to do so')
            self.multiStepJoin(name, domain, ou, account, password)

    def preConnect(self, userName: str, protocol: str, ip: str, hostname: str) -> str:
        logger.debug('Pre connect invoked')

        if protocol == 'rdp':  # If connection is not using rdp, skip adding user
            # Well known SSID for Remote Desktop Users
            groupName = win32security.LookupAccountSid(None, win32security.GetBinarySid(REMOTE_USERS_SID))[0]

            useraAlreadyInGroup = False
            resumeHandle = 0
            while True:
                users, _, resumeHandle = win32net.NetLocalGroupGetMembers(None, groupName, 1, resumeHandle, 32768)
                if userName.lower() in [u['name'].lower() for u in users]:
                    useraAlreadyInGroup = True
                    break
                if resumeHandle == 0:
                    break

            if not useraAlreadyInGroup:
                logger.debug('User not in group, adding it')
                self._user = userName
                try:
                    userSSID = win32security.LookupAccountName(None, userName)[0]
                    win32net.NetLocalGroupAddMembers(None, groupName, 0, [{'sid': userSSID}])
                except Exception as e:
                    logger.error('Exception adding user to Remote Desktop Users: {}'.format(e))
            else:
                self._user = None
                logger.debug('User {} already in group'.format(userName))

        return super().preConnect(userName, protocol, ip, hostname)

    def ovLogon(self, username: str, password: str) -> str:
        """
        Logon on oVirt agent
        currently not used.
        """
        # Compose packet for ov
        usernameBytes = username.encode()
        passwordBytes = username.encode()
        packet = struct.pack('!I', len(usernameBytes)) + usernameBytes + struct.pack('!I', len(passwordBytes)) + passwordBytes
        # Send packet with username/password to ov pipe
        operations.writeToPipe("\\\\.\\pipe\\VDSMDPipe", packet, True)
        return 'done'

    def onLogout(self, userName) -> None:
        logger.debug('Windows onLogout invoked: {}, {}'.format(user, self._user))
        try:
            p = win32security.GetBinarySid(REMOTE_USERS_SID)
            groupName = win32security.LookupAccountSid(None, p)[0]
        except Exception:
            logger.error('Exception getting Windows Group')
            return

        if self._user:
            try:
                win32net.NetLocalGroupDelMembers(None, groupName, [self._user])
            except Exception as e:
                logger.error('Exception removing user from Remote Desktop Users: {}'.format(e))

    def SvcDoRun(self) -> None:  # pylint: disable=too-many-statements, too-many-branches
        '''
        Main service loop
        '''
        logger.debug('running SvcDoRun')
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ''))

        # call the CoInitialize to allow the registration to run in an other
        # thread
        logger.debug('Initializing com...')
        
        pythoncom.CoInitialize()

        if not self.initialize():
            self.notifyStop()
            win32event.WaitForSingleObject(self.hWaitStop, 5000)
            return # Stop daemon if initializes told to do so

        # ********************************
        # * Registers SENS subscriptions *
        # ********************************
        logevent('Registering ISensLogon')
        subscription_guid = '{41099152-498E-11E4-8FD3-10FEED05884B}'
        sl = SensLogon(self)
        subscription_interface = pythoncom.WrapObject(sl)

        event_system = win32com.client.Dispatch(PROGID_EventSystem)

        event_subscription = win32com.client.Dispatch(PROGID_EventSubscription)
        event_subscription.EventClassID = SENSGUID_EVENTCLASS_LOGON
        event_subscription.PublisherID = SENSGUID_PUBLISHER
        event_subscription.SubscriptionName = 'UDS Actor subscription'
        event_subscription.SubscriptionID = subscription_guid
        event_subscription.SubscriberInterface = subscription_interface

        event_system.Store(PROGID_EventSubscription, event_subscription)

        logger.debug('Registered SENS')
        logger.debug('Initialized, setting ready')

        # Initialization is done, set machine to ready for UDS, communicate urls, etc...
        self.setReady()

        # *********************
        # * Main Service loop *
        # *********************
        # Counter used to check ip changes only once every 10 seconds, for
        # example
        counter = 0
        while self._isAlive:
            counter += 1
            # Process SENS messages, This will be a bit asyncronous (1 second delay)
            pythoncom.PumpWaitingMessages()

            if counter >= 10:  # Once every 15 seconds
                counter = 0
                self.checkIpsChanged()

            # In milliseconds, will break
            win32event.WaitForSingleObject(self.hWaitStop, 1000)

        logger.debug('Exited main loop, deregistering SENS')

        # *******************************************
        # * Remove SENS subscription before exiting *
        # *******************************************
        event_system.Remove(PROGID_EventSubscription, "SubscriptionID == " + subscription_guid)

        self.notifyStop()