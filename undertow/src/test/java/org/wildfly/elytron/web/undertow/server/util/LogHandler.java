/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2016 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.elytron.web.undertow.server.util;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.String.format;
import static org.junit.Assert.assertTrue;

/**
 * Utility class for parsing log files and asserting the presence of log records – for testing purposes.
 *
 * @author <a href="mailto:mskaceli@redhat.com">Marek Skacelik</a>
 */
public class LogHandler {
    private final String logFilePath;
    // based on the "%d{HH:mm:ss,SSS} %-5p [%c] (%t) %s%e%n" => only grouping level and message
    private static final Pattern LOG_PATTERN = Pattern.compile("\\s+(\\w{4,5})\\s+\\[.*?]\\s+\\(.*?\\)\\s+(.*)$");
    private final List<LogRecord> logRecords = new ArrayList<>();

    public LogHandler(String logFilePath) {
        if (logFilePath == null) {
            throw new IllegalArgumentException("Path to log file must not be null");
        }
        this.logFilePath = logFilePath;
    }

    public void assertLogsContain(String message, Level level) throws IOException {
        loadLogs();
        assertTrue(format("Expected log record with level '%s' and message '%s' to be present, the content of all the logs are: %s", level, message, stringifyLogs()),
                logRecords.stream().anyMatch(logRecord -> logRecord.getLevel().equals(level) && logRecord.getMessage().contains(message)));
    }

    public void assertLogsContain(String message) throws IOException {
        loadLogs();
        assertTrue(format("Expected log record with message '%s' to be present, the content of all the logs are: %s", message, stringifyLogs()),
                logRecords.stream().anyMatch(logRecord -> logRecord.getMessage().contains(message)));
    }

    public void assertLogsDoNotContain(String message) throws IOException {
        loadLogs();
        assertTrue(format("Expected log record with message '%s' to be absent but it was found in the logs, the content of all the logs are: %s", message, stringifyLogs()),
                logRecords.stream().noneMatch(logRecord -> logRecord.getMessage().contains(message)));
    }

    public String stringifyLogs() {
        StringBuilder logs = new StringBuilder();
        logRecords.forEach(logRecord -> logs.append(logRecord.getLevel()).append(": ").append(logRecord.getMessage()).append("\n"));
        return logs.toString();
    }

    private void loadLogs() throws IOException {
        logRecords.clear();
        try (BufferedReader reader = new BufferedReader(new FileReader(logFilePath))) {
            String line;

            // due to multiline stack traces
            StringBuilder messageBuilder = new StringBuilder();
            String currentLevel = null;

            while ((line = reader.readLine()) != null) {
                Matcher matcher = LOG_PATTERN.matcher(line);
                if (matcher.find()) {
                    // New log entry found
                    if (currentLevel != null) {
                        // Process the previous log entry
                        createLogRecord(currentLevel, messageBuilder.toString().trim());
                        messageBuilder.setLength(0); // Clear the message builder for another log entry
                    }
                    currentLevel = matcher.group(1);
                    messageBuilder.append(matcher.group(2)).append("\n"); // Append the first line of the message
                } else if (currentLevel != null) {
                    // Continuation of the current log entry (stack trace, etc.)
                    messageBuilder.append(line).append("\n");
                }
            }
            // Process the last log entry
            if (currentLevel != null) {
                createLogRecord(currentLevel, messageBuilder.toString().trim());
            }
        } catch (NoSuchFileException e) {
            throw new IllegalStateException(format("Log file %s does not exist", logFilePath), e);
        }
    }

    private void createLogRecord(String level, String message) {
        Level logLevel = Level.parse(level);
        LogRecord logRecord = new LogRecord(logLevel, message);
        logRecords.add(logRecord);
    }

}
