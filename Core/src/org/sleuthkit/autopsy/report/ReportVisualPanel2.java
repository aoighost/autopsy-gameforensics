/*
 * Autopsy Forensic Browser
 *
 * Copyright 2013 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
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
package org.sleuthkit.autopsy.report;

import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.ListCellRenderer;
import javax.swing.ListModel;
import javax.swing.event.ListDataListener;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.datamodel.Tags;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.TskCoreException;

public final class ReportVisualPanel2 extends JPanel {
    private static final Logger logger = Logger.getLogger(ReportVisualPanel2.class.getName());
    private ReportWizardPanel2 wizPanel;
    
    private Map<String, Boolean> tagStates = new LinkedHashMap<>();
    private List<String> tags = new ArrayList<>();
    
    ArtifactSelectionDialog dialog = new ArtifactSelectionDialog(new JFrame(), true);
    private Map<ARTIFACT_TYPE, Boolean> artifactStates = new EnumMap<>(ARTIFACT_TYPE.class);
    private List<ARTIFACT_TYPE> artifacts = new ArrayList<>();
    
    private TagsListModel tagsModel;
    private TagsListRenderer tagsRenderer;

    /**
     * Creates new form ReportVisualPanel2
     */
    public ReportVisualPanel2(ReportWizardPanel2 wizPanel) {
        initComponents();
        initTags();
        initArtifactTypes();
        tagsList.setEnabled(false);
        selectAllButton.setEnabled(false);
        deselectAllButton.setEnabled(false);
        allResultsRadioButton.setSelected(true);
        this.wizPanel = wizPanel;
    }
    
    // Initialize the list of Tags
    private void initTags() {
        for(String tag : Tags.getTagNamesFromCurrentCase()) {
            tagStates.put(tag, Boolean.FALSE);
        }
        tags.addAll(tagStates.keySet());
        
        tagsModel = new TagsListModel();
        tagsRenderer = new TagsListRenderer();
        tagsList.setModel(tagsModel);
        tagsList.setCellRenderer(tagsRenderer);
        tagsList.setVisibleRowCount(-1);
        
        // Add the ability to enable and disable Tag checkboxes to the list
        tagsList.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent evt) {
                JList list = (JList) evt.getSource();
                int index = list.locationToIndex(evt.getPoint());
                String value = (String) tagsModel.getElementAt(index);
                tagStates.put(value, !tagStates.get(value));
                list.repaint();
                updateFinishButton();
            }
        });
        
    }
    
    // Initialize the list of Artifacts
    private void initArtifactTypes() {
        
        try {
             ArrayList<BlackboardArtifact.ARTIFACT_TYPE> doNotReport = new ArrayList();
            doNotReport.add(BlackboardArtifact.ARTIFACT_TYPE.TSK_GEN_INFO);
            
            artifacts = Case.getCurrentCase().getSleuthkitCase().getBlackboardArtifactTypesInUse();
            
            artifacts.removeAll(doNotReport);
            
            artifactStates = new EnumMap<>(ARTIFACT_TYPE.class);
            for (ARTIFACT_TYPE type : artifacts) { 
                artifactStates.put(type, Boolean.TRUE);
            }
        } catch (TskCoreException ex) {
            Logger.getLogger(ReportVisualPanel2.class.getName()).log(Level.SEVERE, "Error getting list of artifacts in use: " + ex.getLocalizedMessage(), ex);
            return;
        }
    }

    @Override
    public String getName() {
        return "Configure HTML and Excel reports";
    }
    
    /**
     * @return the enabled/disabled state of all Artifacts
     */
    Map<ARTIFACT_TYPE, Boolean> getArtifactStates() {
        return artifactStates;
    }
    
    /**
     * @return the enabled/disabled state of all Tags
     */
    Map<String, Boolean> getTagStates() {
        return tagStates;
    }
    
    private boolean areTagsSelected() {
        boolean result = false;
        for (Entry<String, Boolean> entry: tagStates.entrySet()) {
            if (entry.getValue()) {
                result = true;
            }
        }
        return result;
    }
    
    private boolean areArtifactsSelected() {
        boolean result = false;
        for (Entry<ARTIFACT_TYPE, Boolean> entry: artifactStates.entrySet()) {
            if (entry.getValue()) {
                result = true;
            }
        }
        return result;
    }
    
    private void updateFinishButton() {
        if (taggedResultsRadioButton.isSelected()) {
            wizPanel.setFinish(areTagsSelected());
        } else {
            wizPanel.setFinish(areArtifactsSelected());
        }
    }
    
    /**
     * @return true if the Tags radio button is selected, false otherwise
     */
    boolean isTaggedResultsRadioButtonSelected() {
        return taggedResultsRadioButton.isSelected();
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        optionsButtonGroup = new javax.swing.ButtonGroup();
        taggedResultsRadioButton = new javax.swing.JRadioButton();
        allResultsRadioButton = new javax.swing.JRadioButton();
        dataLabel = new javax.swing.JLabel();
        selectAllButton = new javax.swing.JButton();
        deselectAllButton = new javax.swing.JButton();
        tagsScrollPane = new javax.swing.JScrollPane();
        tagsList = new javax.swing.JList();
        advancedButton = new javax.swing.JButton();

        setPreferredSize(new java.awt.Dimension(650, 250));

        optionsButtonGroup.add(taggedResultsRadioButton);
        org.openide.awt.Mnemonics.setLocalizedText(taggedResultsRadioButton, org.openide.util.NbBundle.getMessage(ReportVisualPanel2.class, "ReportVisualPanel2.taggedResultsRadioButton.text")); // NOI18N
        taggedResultsRadioButton.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                taggedResultsRadioButtonStateChanged(evt);
            }
        });

        optionsButtonGroup.add(allResultsRadioButton);
        org.openide.awt.Mnemonics.setLocalizedText(allResultsRadioButton, org.openide.util.NbBundle.getMessage(ReportVisualPanel2.class, "ReportVisualPanel2.allResultsRadioButton.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(dataLabel, org.openide.util.NbBundle.getMessage(ReportVisualPanel2.class, "ReportVisualPanel2.dataLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(selectAllButton, org.openide.util.NbBundle.getMessage(ReportVisualPanel2.class, "ReportVisualPanel2.selectAllButton.text")); // NOI18N
        selectAllButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                selectAllButtonActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(deselectAllButton, org.openide.util.NbBundle.getMessage(ReportVisualPanel2.class, "ReportVisualPanel2.deselectAllButton.text")); // NOI18N
        deselectAllButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deselectAllButtonActionPerformed(evt);
            }
        });

        tagsList.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        tagsList.setLayoutOrientation(javax.swing.JList.VERTICAL_WRAP);
        tagsScrollPane.setViewportView(tagsList);

        org.openide.awt.Mnemonics.setLocalizedText(advancedButton, org.openide.util.NbBundle.getMessage(ReportVisualPanel2.class, "ReportVisualPanel2.advancedButton.text")); // NOI18N
        advancedButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                advancedButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(taggedResultsRadioButton)
                            .addComponent(allResultsRadioButton)
                            .addComponent(dataLabel))
                        .addGap(0, 481, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(21, 21, 21)
                        .addComponent(tagsScrollPane)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(advancedButton, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(deselectAllButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(selectAllButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(dataLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(allResultsRadioButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(taggedResultsRadioButton)
                .addGap(7, 7, 7)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(selectAllButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(deselectAllButton)
                        .addGap(0, 70, Short.MAX_VALUE))
                    .addComponent(tagsScrollPane))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(advancedButton)
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private void taggedResultsRadioButtonStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_taggedResultsRadioButtonStateChanged
        tagsList.setEnabled(taggedResultsRadioButton.isSelected());
        selectAllButton.setEnabled(taggedResultsRadioButton.isSelected());
        deselectAllButton.setEnabled(taggedResultsRadioButton.isSelected());
        advancedButton.setEnabled(!taggedResultsRadioButton.isSelected());
        updateFinishButton();
    }//GEN-LAST:event_taggedResultsRadioButtonStateChanged

    private void selectAllButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_selectAllButtonActionPerformed
        for (String tag : tags) {
            tagStates.put(tag, Boolean.TRUE);
        }
        tagsList.repaint();
        wizPanel.setFinish(true);
    }//GEN-LAST:event_selectAllButtonActionPerformed

    private void deselectAllButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deselectAllButtonActionPerformed
        for (String tag : tags) {
            tagStates.put(tag, Boolean.FALSE);
        }
        tagsList.repaint();
        wizPanel.setFinish(false);
    }//GEN-LAST:event_deselectAllButtonActionPerformed

    private void advancedButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_advancedButtonActionPerformed
        artifactStates = dialog.display();
        wizPanel.setFinish(areArtifactsSelected());
    }//GEN-LAST:event_advancedButtonActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton advancedButton;
    private javax.swing.JRadioButton allResultsRadioButton;
    private javax.swing.JLabel dataLabel;
    private javax.swing.JButton deselectAllButton;
    private javax.swing.ButtonGroup optionsButtonGroup;
    private javax.swing.JButton selectAllButton;
    private javax.swing.JRadioButton taggedResultsRadioButton;
    private javax.swing.JList tagsList;
    private javax.swing.JScrollPane tagsScrollPane;
    // End of variables declaration//GEN-END:variables
    
    private class TagsListModel implements ListModel {

        @Override
        public int getSize() {
            return tags.size();
        }

        @Override
        public Object getElementAt(int index) {
            return tags.get(index);
        }

        @Override
        public void addListDataListener(ListDataListener l) {
        }

        @Override
        public void removeListDataListener(ListDataListener l) {
        }
    }
    
    // Render the Tags as JCheckboxes
    private class TagsListRenderer extends JCheckBox implements ListCellRenderer {

        @Override
        public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
            if (value != null) {
                setEnabled(list.isEnabled());
                setSelected(tagStates.get(value.toString()));
                setFont(list.getFont());
                setBackground(list.getBackground());
                setForeground(list.getForeground());
                setText(value.toString());
                return this;
            }
            return new JLabel();
        }
        
    }

}
