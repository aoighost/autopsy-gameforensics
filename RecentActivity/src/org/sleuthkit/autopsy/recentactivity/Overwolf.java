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
 * Overwolf recent activity extraction
 */
public class Overwolf extends Extract {

    private static final String owquery = "SELECT urls.url, urls.title, urls.visit_count, urls.typed_count, "
            + "urls.last_visit_time, urls.hidden, visits.visit_time, (SELECT urls.url FROM urls WHERE urls.id=visits.url) as from_visit, visits.transition FROM urls, visits WHERE urls.id = visits.url";
    private static final String owcookiequery = "select name, value, host_key, expires_utc,last_access_utc, creation_utc from cookies";
    private static final String owdownloadquery = "select full_path, url, start_time, received_bytes from downloads";
    private final Logger logger = Logger.getLogger(this.getClass().getName());
    public int OverwolfCount = 0;
    final public static String MODULE_VERSION = "1.0";
    private IngestServices services;

    //hide public constructor to prevent from instantiation by ingest module loader
    Overwolf() {
        moduleName = "Overwolf";
    }

    @Override
    public String getVersion() {
        return MODULE_VERSION;
    }


    @Override
    public void process(PipelineContext<IngestModuleDataSource>pipelineContext, Content dataSource, IngestDataSourceWorkerController controller) {
        this.getHistory(dataSource, controller);
        this.getCookie(dataSource, controller);
        this.getDefaultProfileCookie(dataSource, controller);
        this.getDownload(dataSource, controller);
    }

    private void getHistory(Content dataSource, IngestDataSourceWorkerController controller) {

        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> historyFiles = null;
        try {
            historyFiles = fileManager.findFiles(dataSource, "History", "Overwolf/BrowserCache/Default");
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error when trying to get Overwolf history files.", ex);
        }
        
        // get only the allocated ones, for now
        List<AbstractFile> allocatedHistoryFiles = new ArrayList<>();
        for (AbstractFile historyFile : historyFiles) {
            if (historyFile.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.ALLOC)) {
                allocatedHistoryFiles.add(historyFile);
            }
        }
        
        // log a message if we don't have any allocated history files
        if (allocatedHistoryFiles.size() == 0) {
            logger.log(Level.INFO, "Could not find any allocated Overwolf history files.");
            return;
        }

        int j = 0;
        while (j < historyFiles.size()) {
            String temps = RAImageIngestModule.getRATempPath(currentCase, "overwolf") + File.separator + historyFiles.get(j).getName().toString() + j + ".db";
            int errors = 0;
            final AbstractFile historyFile = historyFiles.get(j++);
            if (historyFile.getSize() == 0) {
                continue;
            }
            try {
                ContentUtils.writeToFile(historyFile, new File(temps));
            } catch (IOException ex) {
                logger.log(Level.SEVERE, "Error writing temp sqlite db for Overwolf web history artifacts.{0}", ex);
                this.addErrorMessage(this.getName() + ": Error while trying to analyze file:" + historyFile.getName());
                continue;
            }
            File dbFile = new File(temps);
            if (controller.isCancelled()) {
                dbFile.delete();
                break;
            }
            List<HashMap<String, Object>> tempList = null;
            tempList = this.dbConnect(temps, owquery);
            logger.log(Level.INFO, moduleName + "- Now getting history from " + temps + " with " + tempList.size() + "artifacts identified.");
            for (HashMap<String, Object> result : tempList) {

                Collection<BlackboardAttribute> bbattributes = new ArrayList<BlackboardAttribute>();
                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_URL.getTypeID(), "Recent Activity", ((result.get("url").toString() != null) ? result.get("url").toString() : "")));
                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_URL_DECODED.getTypeID(), "Recent Activity", ((result.get("url").toString() != null) ? EscapeUtil.decodeURL(result.get("url").toString()) : "")));
                //TODO Revisit usage of deprecated constructor per TSK-583
                //bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_LAST_ACCESSED.getTypeID(), "Recent Activity", "Last Visited", ((Long.valueOf(result.get("last_visit_time").toString())) / 10000000)));
                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), "Recent Activity", (((Long.valueOf(result.get("last_visit_time").toString())) / 1000000) - 11644473600L)));
//                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED.getTypeID(), "Recent Activity", ((Long.valueOf(result.get("last_visit_time").toString())) / 10000000)));
                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_REFERRER.getTypeID(), "Recent Activity", ((result.get("from_visit").toString() != null) ? result.get("from_visit").toString() : "")));
                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), "Recent Activity", ((result.get("title").toString() != null) ? result.get("title").toString() : "")));
                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), "Recent Activity", "Overwolf"));
                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), "Recent Activity", (Util.extractDomain((result.get("url").toString() != null) ? result.get("url").toString() : ""))));
                this.addArtifact(ARTIFACT_TYPE.TSK_WEB_HISTORY, historyFile, bbattributes);

            }
            if (errors > 0) {
                this.addErrorMessage(this.getName() + ": Error parsing " + errors + " Overwolf web history artifacts.");
            }

            dbFile.delete();
        }

        services.fireModuleDataEvent(new ModuleDataEvent("Recent Activity", BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY));
    }

    //COOKIES section
    // This gets the cookie info
    private void getCookie(Content dataSource, IngestDataSourceWorkerController controller) {
        
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> cookiesFiles = null;
        try {
            cookiesFiles = fileManager.findFiles(dataSource, "Cookies", "Overwolf/BrowserCache");
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error when trying to get Overwolf history files.", ex);
        }

        int j = 0;
        if (cookiesFiles != null && !cookiesFiles.isEmpty()) {
            while (j < cookiesFiles.size()) {
                AbstractFile cookiesFile = cookiesFiles.get(j++);
                String temps = RAImageIngestModule.getRATempPath(currentCase, "overwolf") + File.separator + cookiesFile.getName().toString() + j + ".db";
                int errors = 0;
                try {
                    ContentUtils.writeToFile(cookiesFile, new File(temps));
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, "Error writing temp sqlite db for Overwolf cookie artifacts.{0}", ex);
                    this.addErrorMessage(this.getName() + ": Error while trying to analyze file:" + cookiesFile.getName());
                    continue;
                }
                File dbFile = new File(temps);
                if (controller.isCancelled()) {
                    dbFile.delete();
                    break;
                }

                List<HashMap<String, Object>> tempList = this.dbConnect(temps, owcookiequery);
                logger.log(Level.INFO, moduleName + "- Now getting cookies from " + temps + " with " + tempList.size() + "artifacts identified.");
                for (HashMap<String, Object> result : tempList) {
                    Collection<BlackboardAttribute> bbattributes = new ArrayList<BlackboardAttribute>();
                    //TODO Revisit usage of deprecated constructor as per TSK-583
                    //bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), "Recent Activity", "Title", ((result.get("name").toString() != null) ? result.get("name").toString() : "")));
                    //bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), "Recent Activity", "Last Visited", ((Long.valueOf(result.get("last_access_utc").toString())) / 10000000)));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), "Recent Activity", ((result.get("name").toString() != null) ? result.get("name").toString() : "")));
//                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), "Recent Activity", ((Long.valueOf(result.get("last_access_utc").toString())) / 10000000)));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), "Recent Activity", (((Long.valueOf(result.get("last_access_utc").toString())) / 1000000) - 11644473600L)));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_VALUE.getTypeID(), "Recent Activity", ((result.get("value").toString() != null) ? result.get("value").toString() : "")));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), "Recent Activity", "Overwolf"));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_URL.getTypeID(), "Recent Activity", ((result.get("host_key").toString() != null) ? result.get("host_key").toString() : "")));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_URL_DECODED.getTypeID(), "Recent Activity", ((result.get("host_key").toString() != null) ? EscapeUtil.decodeURL(result.get("host_key").toString()) : "")));
                    String domain = result.get("host_key").toString();
                    domain = domain.replaceFirst("^\\.+(?!$)", "");
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), "Recent Activity", domain));
                    this.addArtifact(ARTIFACT_TYPE.TSK_WEB_COOKIE, cookiesFile, bbattributes);

                }
                if (errors > 0) {
                    this.addErrorMessage(this.getName() + ": Error parsing " + errors + " Overwolf cookie artifacts.");
                }
        
                dbFile.delete();
            }

            services.fireModuleDataEvent(new ModuleDataEvent("Recent Activity", BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_COOKIE));
        }
    }

    //Default profile COOKIES section
    // This gets the cookie info from the default profile
    private void getDefaultProfileCookie(Content dataSource, IngestDataSourceWorkerController controller) {
        
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> cookiesFiles = null;
        try {
            cookiesFiles = fileManager.findFiles(dataSource, "Cookies", "Overwolf/BrowserCache/Default/Cookies");
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error when trying to get Overwolf history files.", ex);
        }

        int j = 0;
        if (cookiesFiles != null && !cookiesFiles.isEmpty()) {
            while (j < cookiesFiles.size()) {
                AbstractFile cookiesFile = cookiesFiles.get(j++);
                String temps = RAImageIngestModule.getRATempPath(currentCase, "overwolf") + File.separator + cookiesFile.getName().toString() + j + ".db";
                int errors = 0;
                try {
                    ContentUtils.writeToFile(cookiesFile, new File(temps));
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, "Error writing temp sqlite db for Overwolf cookie artifacts.{0}", ex);
                    this.addErrorMessage(this.getName() + ": Error while trying to analyze file:" + cookiesFile.getName());
                    continue;
                }
                File dbFile = new File(temps);
                if (controller.isCancelled()) {
                    dbFile.delete();
                    break;
                }

                List<HashMap<String, Object>> tempList = this.dbConnect(temps, owcookiequery);
                logger.log(Level.INFO, moduleName + "- Now getting cookies from " + temps + " with " + tempList.size() + "artifacts identified.");
                for (HashMap<String, Object> result : tempList) {
                    Collection<BlackboardAttribute> bbattributes = new ArrayList<BlackboardAttribute>();
                    //TODO Revisit usage of deprecated constructor as per TSK-583
                    //bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), "Recent Activity", "Title", ((result.get("name").toString() != null) ? result.get("name").toString() : "")));
                    //bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), "Recent Activity", "Last Visited", ((Long.valueOf(result.get("last_access_utc").toString())) / 10000000)));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), "Recent Activity", ((result.get("name").toString() != null) ? result.get("name").toString() : "")));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), "Recent Activity", (((Long.valueOf(result.get("last_access_utc").toString())) / 1000000) - 11644473600L)));
//                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), "Recent Activity", ((Long.valueOf(result.get("last_access_utc").toString())) / 10000000)));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_VALUE.getTypeID(), "Recent Activity", ((result.get("value").toString() != null) ? result.get("value").toString() : "")));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), "Recent Activity", "Overwolf"));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_URL.getTypeID(), "Recent Activity", ((result.get("host_key").toString() != null) ? result.get("host_key").toString() : "")));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_URL_DECODED.getTypeID(), "Recent Activity", ((result.get("host_key").toString() != null) ? EscapeUtil.decodeURL(result.get("host_key").toString()) : "")));
                    String domain = result.get("host_key").toString();
                    domain = domain.replaceFirst("^\\.+(?!$)", "");
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), "Recent Activity", domain));
                    this.addArtifact(ARTIFACT_TYPE.TSK_WEB_COOKIE, cookiesFile, bbattributes);

                }
                if (errors > 0) {
                    this.addErrorMessage(this.getName() + ": Error parsing " + errors + " Overwolf cookie artifacts.");
                }
        
                dbFile.delete();
            }

            services.fireModuleDataEvent(new ModuleDataEvent("Recent Activity", BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_COOKIE));
        }
    }

    //Downloads section
    // This gets the downloads info
    private void getDownload(Content dataSource, IngestDataSourceWorkerController controller) {
        
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> historyFiles = null;
        try {
            historyFiles = fileManager.findFiles(dataSource, "History", "Overwolf/BrowserCache/Default");
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error when trying to get Overwolf history files.", ex);
        }

        int j = 0;
        if (historyFiles != null && !historyFiles.isEmpty()) {
            while (j < historyFiles.size()) {
                AbstractFile historyFile = historyFiles.get(j++);
                if (historyFile.getSize() == 0) {
                    continue;
                }
                String temps = RAImageIngestModule.getRATempPath(currentCase, "overwolf") + File.separator + historyFile.getName().toString() + j + ".db";
                int errors = 0;
                try {
                    ContentUtils.writeToFile(historyFile, new File(temps));
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, "Error writing temp sqlite db for Overwolf download artifacts.{0}", ex);
                    this.addErrorMessage(this.getName() + ": Error while trying to analyze file:" + historyFile.getName());
                    continue;
                }
                File dbFile = new File(temps);
                if (controller.isCancelled()) {
                    dbFile.delete();
                    break;
                }

                List<HashMap<String, Object>> tempList = this.dbConnect(temps, owdownloadquery);
                logger.log(Level.INFO, moduleName + "- Now getting downloads from " + temps + " with " + tempList.size() + "artifacts identified.");
                for (HashMap<String, Object> result : tempList) {
                    Collection<BlackboardAttribute> bbattributes = new ArrayList<BlackboardAttribute>();
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PATH.getTypeID(), "Recent Activity", (result.get("full_path").toString())));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PATH_ID.getTypeID(), "Recent Activity", Util.findID(dataSource, (result.get("full_path").toString()))));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_URL.getTypeID(), "Recent Activity", ((result.get("url").toString() != null) ? result.get("url").toString() : "")));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_URL_DECODED.getTypeID(), "Recent Activity", ((result.get("url").toString() != null) ? EscapeUtil.decodeURL(result.get("url").toString()) : "")));
                    Long time = (Long.valueOf(result.get("start_time").toString()));
                    String Tempdate = time.toString();
                    time = Long.valueOf(Tempdate) / 10000000;
                    //TODO Revisit usage of deprecated constructor as per TSK-583
                    //bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_LAST_ACCESSED.getTypeID(), "Recent Activity", "Last Visited", time));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED.getTypeID(), "Recent Activity", time));
                    String domain = Util.extractDomain((result.get("url").toString() != null) ? result.get("url").toString() : "");
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), "Recent Activity", domain));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), "Recent Activity", "Overwolf"));
                    this.addArtifact(ARTIFACT_TYPE.TSK_WEB_DOWNLOAD, historyFile, bbattributes);

                }
                if (errors > 0) {
                    this.addErrorMessage(this.getName() + ": Error parsing " + errors + " Overwolf download artifacts.");
                }
       
                dbFile.delete();
            }

            services.fireModuleDataEvent(new ModuleDataEvent("Recent Activity", BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_DOWNLOAD));
        }
    }


    @Override
    public void init(IngestModuleInit initContext) {
        services = IngestServices.getDefault();
    }

    @Override
    public void complete() {
        logger.info("Overwolf Extract has completed");
    }

    @Override
    public void stop() {
        logger.info("Attempted to stop Overwolf extract, but operation is not supported; skipping...");
    }

    @Override
    public String getDescription() {
        return "Extracts activity from Overwolf.";
    }


    @Override
    public boolean hasBackgroundJobsRunning() {
        return false;
    }
}
