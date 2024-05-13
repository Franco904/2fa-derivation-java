package org.example.utils;

import java.io.*;

public class FileUtils {
    public static final File resourcesFolder = new File("src/main/resources");

    public static void createIfNotExists(File file) throws IOException {
        if (!file.exists()) {
            boolean fileWasCreated = file.createNewFile();
            if (!fileWasCreated)
                throw new IOException("Não foi possível criar o arquivo em " + resourcesFolder.getPath());
        }
    }

    public static String getLine(File file, String text) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(text)) {
                    return line;
                }
            }
        }
        return null;
    }

    public static String getFirstLineOrNull(File file) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            return reader.readLine();
        }
    }

    public static boolean hasLine(File file, String text) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(text)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static void putLine(File file, String text) throws IOException {
        try (FileWriter writer = new FileWriter(file, true)) {
            if (getFirstLineOrNull(file) == null) {
                writer.write(text);
            } else {
                writer.write("\n" + text);
            }
        }
    }
}
