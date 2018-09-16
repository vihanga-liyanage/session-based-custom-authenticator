/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.session.based.custom.authenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserOperationEventListener;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SessionBasedCustomAuthenticator extends AbstractUserOperationEventListener {

    private static Log log = LogFactory.getLog(SessionBasedCustomAuthenticator.class);
    private static final String SESSION_DATA_RETRIEVE_QUERY = "SELECT `ID` FROM IDN_CUSTOM_SESSION_DATA " +
            "WHERE `USER`=? LIMIT 1";

    @Override
    public int getExecutionOrderId() {

        //This listener should execute before the IdentityMgtEventListener
        //Hence the number should be < 1357 (Execution order ID of IdentityMgtEventListener)
        return 1356;
    }

    @Override
    public boolean doPreAuthenticate(String userName, Object credential, UserStoreManager userStoreManager) {

        // This method should return true for the authentication process to continue.
        if (isActiveSessionsExists(userName)) {
            log.warn("Unsuccessful login attempt for the user " + userName + ". User already have an " +
                    "active session.");
            return false;
        } else {
            return true;
        }
    }

    private boolean isActiveSessionsExists(String username) {

        log.info("Retrieving session data records for the user: " + username);

        int id = 0;
        PreparedStatement prepStmt = null;
        Connection connection = null;

        // Get existing session records.
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(SESSION_DATA_RETRIEVE_QUERY);
            prepStmt.setString(1, username);
            ResultSet resultSet = prepStmt.executeQuery();

            // This result set will have either 0 or only 1 record.
            while (resultSet.next()) {
                id = resultSet.getInt(1);
            }

            connection.commit();
        } catch (SQLException e) {
            log.error("Error while retrieving custom user session information for the user: " + username, e);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
            IdentityDatabaseUtil.closeConnection(connection);
        }

        // If the id is 0, that means there are no active sessions for this user.
        return (id != 0);
    }
}
