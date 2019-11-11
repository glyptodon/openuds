# -*- coding: utf-8 -*-

#
# Copyright (c) 2016 Virtual Cable S.L.
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

"""
@author: Adolfo Gómez, dkmaster at dkmon dot com
"""
import logging
import typing

from django.utils.translation import ugettext_lazy as _

from uds.core import services
from uds.core.util.state import State
from uds.core.util.auto_attributes import AutoAttributes

# Not imported at runtime, just for type checking
if typing.TYPE_CHECKING:
    from uds import models
    from .service_base import IPServiceBase

logger = logging.getLogger(__name__)


class IPMachineDeployed(services.UserDeployment, AutoAttributes):
    suggestedTime = 10

    _ip: str
    _reason: str
    _state: str

    def __init__(self, environment, **kwargs):
        AutoAttributes.__init__(self, ip=str, reason=str, state=str)
        services.UserDeployment.__init__(self, environment, **kwargs)
        self._state = State.FINISHED

    # Utility overrides for type checking...
    def service(self) -> 'IPServiceBase':
        return typing.cast('IPServiceBase', super().service())

    def setIp(self, ip: str) -> None:
        logger.debug('Setting IP to %s (ignored)', ip)

    def getIp(self) -> str:
        return self._ip.split('~')[0]

    def getName(self) -> str:
        return _("IP ") + self._ip.replace('~', ':')

    def getUniqueId(self) -> str:
        return self._ip.replace('~', ':')

    def setReady(self) -> str:
        self._state = State.FINISHED
        return self._state

    def __deploy(self) -> str:
        ip = self.service().getUnassignedMachine()
        if ip is None:
            self._reason = 'No machines left'
            self._state = State.ERROR
        else:
            self._ip = ip
            self._state = State.FINISHED
        dbService = self.dbservice()
        if dbService:
            dbService.setInUse(True)
            dbService.save()
        return self._state

    def deployForUser(self, user: 'models.User') -> str:
        logger.debug("Starting deploy of %s for user %s", self._ip, user)
        return self.__deploy()

    def checkState(self) -> str:
        return self._state

    def reasonOfError(self) -> str:
        """
        If a publication produces an error, here we must notify the reason why it happened. This will be called just after
        publish or checkPublishingState if they return State.ERROR
        """
        return self._reason

    def destroy(self) -> str:
        if self._ip != '':
            self.service().unassignMachine(self._ip)
        self._state = State.FINISHED
        return self._state

    def cancel(self) -> str:
        return self.destroy()
