 /*
 *
 * Autopsy Forensic Browser
 * 
 * Copyright 2012-2013 Basis Technology Corp.
 * 
 * Copyright 2012 42six Solutions.
 * 
 * Copyright 2013 Peter Clemenko III
 *
 * Project Contact/Architect: carrier <at> sleuthkit <dot> org
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.autopsy.recentactivity;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.autopsy.datamodel.ContentUtils;
import java.util.logging.Level;
import org.sleuthkit.autopsy.coreutils.Logger;
import java.util.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.coreutils.EscapeUtil;
import org.sleuthkit.autopsy.ingest.PipelineContext;
import org.sleuthkit.autopsy.ingest.IngestDataSourceWorkerController;
import org.sleuthkit.autopsy.ingest.IngestModuleDataSource;
import org.sleuthkit.autopsy.ingest.IngestModuleInit;
import org.sleuthkit.autopsy.ingest.ModuleDataEvent;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskData;

/**
 * Steam Browser recent activity extraction
 */
public class Dota2 extends Extract {

    private static final String dota2browsercookiequery = "select name, value, host_key, expires_utc,last_access_utc, creation_utc from cookies";
    private final Logger logger = Logger.getLogger(this.getClass().getName());
    public int Dota2BrowserCount = 0;
    final public static String MODULE_VERSION = "1.0";
    private IngestServices services;

    //hide public constructor to prevent from instantiation by ingest module loader
    Dota2() {
        moduleName = "Dota 2";
    }

    @Override
    public String getVersion() {
        return MODULE_VERSION;
    }


    @Override
    public void process(PipelineContext<IngestModuleDataSource>pipelineContext, Content dataSource, IngestDataSourceWorkerController controller) {
        this.getDota2Cookies(dataSource, controller);
        this.getDota2TestCookies(dataSource, controller);
    }

    //COOKIES section
    // This gets the cookie info
    private void getDota2Cookies(Content dataSource, IngestDataSourceWorkerController controller) {
        
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> cookiesFiles = null;
        try {
            cookiesFiles = fileManager.findFiles(dataSource, "Cookies", "SteamApps/Common/dota 2 beta/dota/config/html");
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error when trying to get Dota 2 cookie files.", ex);
        }

        int j = 0;
        if (cookiesFiles != null && !cookiesFiles.isEmpty()) {
            while (j < cookiesFiles.size()) {
                AbstractFile cookiesFile = cookiesFiles.get(j++);
                String temps = currentCase.getTempDirectory() + File.separator + cookiesFile.getName().toString() + j + ".db";
                int errors = 0;
                try {
                    ContentUtils.writeToFile(cookiesFile, new File(temps));
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, "Error writing temp sqlite db for Dota 2 cookie artifacts.{0}", ex);
                    this.addErrorMessage(this.getName() + ": Error while trying to analyze file:" + cookiesFile.getName());
                }
                File dbFile = new File(temps);
                if (controller.isCancelled()) {
                    dbFile.delete();
                    break;
                }

                List<HashMap<String, Object>> tempList = this.dbConnect(temps, dota2browsercookiequery);
                logger.log(Level.INFO, moduleName + "- Now getting cookies from " + temps + " with " + tempList.size() + "artifacts identified.");
                for (HashMap<String, Object> result : tempList) {
                    Collection<BlackboardAttribute> bbattributes = new ArrayList<BlackboardAttribute>();
                    //TODO Revisit usage of deprecated constructor as per TSK-583
                    //bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), "Recent Activity", "Title", ((result.get("name").toString() != null) ? result.get("name").toString() : "")));
                    //bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), "Recent Activity", "Last Visited", ((Long.valueOf(result.get("last_access_utc").toString())) / 10000000)));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), "Recent Activity", ((result.get("name").toString() != null) ? result.get("name").toString() : "")));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), "Recent Activity", (((Long.valueOf(result.get("last_access_utc").toString())) / 1000000) - 11644473600L)));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_VALUE.getTypeID(), "Recent Activity", ((result.get("value").toString() != null) ? result.get("value").toString() : "")));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), "Recent Activity", "Dota 2"));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_URL.getTypeID(), "Recent Activity", ((result.get("host_key").toString() != null) ? result.get("host_key").toString() : "")));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_URL_DECODED.getTypeID(), "Recent Activity", ((result.get("host_key").toString() != null) ? EscapeUtil.decodeURL(result.get("host_key").toString()) : "")));
                    String domain = result.get("host_key").toString();
                    domain = domain.replaceFirst("^\\.+(?!$)", "");
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), "Recent Activity", domain));
                    this.addArtifact(ARTIFACT_TYPE.TSK_WEB_COOKIE, cookiesFile, bbattributes);

                }
                if (errors > 0) {
                    this.addErrorMessage(this.getName() + ": Error parsing " + errors + " Dota 2 cookie artifacts.");
                }
        
                dbFile.delete();
            }

            services.fireModuleDataEvent(new ModuleDataEvent("Recent Activity", BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_COOKIE));
        }
    }

    // testing version of Dota 2, this is a seperate app.
    private void getDota2TestCookies(Content dataSource, IngestDataSourceWorkerController controller) {
        
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> cookiesFiles = null;
        try {
            cookiesFiles = fileManager.findFiles(dataSource, "Cookies", "SteamApps/Common/dota 2 test/dota/config/html");
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error when trying to get Dota 2 Test cookie files.", ex);
        }

        int j = 0;
        if (cookiesFiles != null && !cookiesFiles.isEmpty()) {
            while (j < cookiesFiles.size()) {
                AbstractFile cookiesFile = cookiesFiles.get(j++);
                String temps = currentCase.getTempDirectory() + File.separator + cookiesFile.getName().toString() + j + ".db";
                int errors = 0;
                try {
                    ContentUtils.writeToFile(cookiesFile, new File(temps));
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, "Error writing temp sqlite db for Dota 2 Test cookie artifacts.{0}", ex);
                    this.addErrorMessage(this.getName() + ": Error while trying to analyze file:" + cookiesFile.getName());
                }
                File dbFile = new File(temps);
                if (controller.isCancelled()) {
                    dbFile.delete();
                    break;
                }

                List<HashMap<String, Object>> tempList = this.dbConnect(temps, dota2browsercookiequery);
                logger.log(Level.INFO, moduleName + "- Now getting cookies from " + temps + " with " + tempList.size() + "artifacts identified.");
                for (HashMap<String, Object> result : tempList) {
                    Collection<BlackboardAttribute> bbattributes = new ArrayList<BlackboardAttribute>();
                    //TODO Revisit usage of deprecated constructor as per TSK-583
                    //bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), "Recent Activity", "Title", ((result.get("name").toString() != null) ? result.get("name").toString() : "")));
                    //bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), "Recent Activity", "Last Visited", ((Long.valueOf(result.get("last_access_utc").toString())) / 10000000)));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), "Recent Activity", ((result.get("name").toString() != null) ? result.get("name").toString() : "")));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), "Recent Activity", (((Long.valueOf(result.get("last_access_utc").toString())) / 1000000) - 11644473600L)));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_VALUE.getTypeID(), "Recent Activity", ((result.get("value").toString() != null) ? result.get("value").toString() : "")));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), "Recent Activity", "Dota 2 Test"));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_URL.getTypeID(), "Recent Activity", ((result.get("host_key").toString() != null) ? result.get("host_key").toString() : "")));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_URL_DECODED.getTypeID(), "Recent Activity", ((result.get("host_key").toString() != null) ? EscapeUtil.decodeURL(result.get("host_key").toString()) : "")));
                    String domain = result.get("host_key").toString();
                    domain = domain.replaceFirst("^\\.+(?!$)", "");
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), "Recent Activity", domain));
                    this.addArtifact(ARTIFACT_TYPE.TSK_WEB_COOKIE, cookiesFile, bbattributes);

                }
                if (errors > 0) {
                    this.addErrorMessage(this.getName() + ": Error parsing " + errors + " Dota 2 Test cookie artifacts.");
                }
        
                dbFile.delete();
            }

            services.fireModuleDataEvent(new ModuleDataEvent("Recent Activity", BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_COOKIE));
        }
    }

    @Override
    public void init(IngestModuleInit initContext) {
        services = IngestServices.getDefault();
    }

    @Override
    public void complete() {
        logger.info("Dota 2 Extract has completed");
    }

    @Override
    public void stop() {
        logger.info("Attempted to stop Dota 2 extract, but operation is not supported; skipping...");
    }

    @Override
    public String getDescription() {
        return "Extracts activity from Dota 2.";
    }


    @Override
    public boolean hasBackgroundJobsRunning() {
        return false;
    }
}
