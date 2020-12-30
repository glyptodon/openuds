/*
 * Copyright (c) 2020 Virtual Cable S.L.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright notice,
 *      this list of conditions and the following disclaimer in the documentation
 *      and/or other materials provided with the distribution.
 *    * Neither the name of Virtual Cable S.L. nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.openuds.guacamole.connection;

import com.google.auto.factory.AutoFactory;
import com.google.inject.Inject;
import java.util.Map;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleUnauthorizedException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.simple.SimpleConnection;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.openuds.guacamole.UDSUserContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Connection implementation which uses provided data to communicate with a 
 * remote UDS service to dynamically authorize access to a remote desktop.
 */
@AutoFactory
public class UDSConnection extends SimpleConnection {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(UDSConnection.class);

    /**
     * The name of the single connection that should be exposed to any user
     * that authenticates via UDS.
     */
    public static final String NAME = "UDS";

    /**
     * The unique identifier of the single connection that should be exposed to
     * any user that authenticates via UDS.
     */
    public static final String IDENTIFIER = NAME;

    /**
     * Service for retrieving configuration information.
     */
    @Inject
    private ConnectionService connectionService;

    /**
     * The UDS-specific data that should be provided to the remote UDS service
     * to re-authenticate the user and determine the details of the connection
     * they are authorized to access.
     */
    private final String data;

    /**
     * Creates a new UDSConnection which exposes access to a remote desktop
     * that is dynamically authorized by exchanging arbitrary UDS-specific data
     * with a remote service.
     *
     * @param data
     *     The UDS-specific data that should be provided to the remote UDS
     *     service.
     */
    public UDSConnection(String data) {
        this.data = data;
    }

    @Override
    public String getParentIdentifier() {
        return UDSUserContext.ROOT_CONNECTION_GROUP;
    }

    @Override
    public void setParentIdentifier(String parentIdentifier) {
        throw new UnsupportedOperationException("UDSConnection is read-only.");
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void setName(String name) {
        throw new UnsupportedOperationException("UDSConnection is read-only.");
    }

    @Override
    public String getIdentifier() {
        return IDENTIFIER;
    }

    @Override
    public void setIdentifier(String identifier) {
        throw new UnsupportedOperationException("UDSConnection is read-only.");
    }

    @Override
    public GuacamoleTunnel connect(GuacamoleClientInformation info,
            Map<String, String> tokens) throws GuacamoleException {

        logger.debug("Retrieving connection configuration using data from \"{}\"...", data);

        // Re-validate provided data (do not allow connections if data is no
        // longer valid)
        GuacamoleConfiguration config = connectionService.getConnectionConfiguration(data);
        if (config == null)
            throw new GuacamoleUnauthorizedException("Provided data is invalid or no longer authorized.");

        // Connect with configuration produced from data
        setConfiguration(config);
        return super.connect(info, tokens);

    }

}
