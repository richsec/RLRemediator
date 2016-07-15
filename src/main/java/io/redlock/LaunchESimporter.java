package io.redlock;

import com.google.common.net.InetAddresses;
import io.redlock.common.diconfig.DIConfig;
import io.redlock.common.util.InputValidationUtil;
import org.apache.commons.cli.*;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPInputStream;

@Component
public class LaunchESimporter {

    private static final Logger logger = LoggerFactory.getLogger(LaunchESimporter.class);

    @Autowired
    InputValidationUtil inputValidationUtil;


    public static void main(String[] args) {

        try (AnnotationConfigApplicationContext annotationConfigApplicationContext = new AnnotationConfigApplicationContext(DIConfig.class)) {
            LaunchESimporter annotationConfigApplicationContextBean = annotationConfigApplicationContext.getBean(LaunchESimporter.class);
            annotationConfigApplicationContextBean.runJob(args);
        }

    }

    private void runJob(String args[]) {


        try {

            HelpFormatter formatter = new HelpFormatter();

            Options options = new Options();
            options.addOption("dir", true, "Path to directory containing .gzip'ed CSV files");
            options.addOption("eshost", true, "hostname/ip of elasticsearch");
            options.addOption("port", true, "port # of elasticsearch");
            options.addOption("indexName", true, "index name");
            options.addOption("flushEvery", true, "flush every n messages");

            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);

            String dir = cmd.getOptionValue("dir");
            String eshost = cmd.getOptionValue("eshost");
            String port = cmd.getOptionValue("port");
            String indexName = cmd.getOptionValue("indexName");
            Integer flushEvery = Integer.valueOf(cmd.getOptionValue("flushEvery"));
            if (!inputValidationUtil.checkAllargsNotNull(indexName, dir, eshost, port)) {
                formatter.printHelp("java -jar " + LaunchESimporter.class.getName(), options);
                System.exit(-1);
            }


            Settings settings = Settings.settingsBuilder()
                    .put("cluster.name", "elasticsearch").build();

            Client client = TransportClient.builder().settings(settings).build().
                    addTransportAddress(new InetSocketTransportAddress(InetAddress.getByName(eshost),
                            Integer.valueOf(port)));


            BulkRequestBuilder bulkBuilder = client.prepareBulk();


            final int[] submissionCounter = {0};
            Files.walk(Paths.get(dir)).forEach(filePath -> {
                if (Files.isRegularFile(filePath)) {

                    String filePathToProcess = null;
                    try {
                        filePathToProcess = filePath.toString();
                        logger.info("Processing " + filePathToProcess);

                        FileInputStream fileInputStream = new FileInputStream(filePathToProcess);
                        GZIPInputStream gzipInputStream = new GZIPInputStream(fileInputStream);

                        BufferedReader in = new BufferedReader(new InputStreamReader(gzipInputStream));

                        String line;
                        int ctr = 0;
                        while ((line = in.readLine()) != null) {

                            Map<String, Object> fieldMap = new HashMap<>();

                            String[] fields = line.split(",");

                            fieldMap.put("rlk_uuid", fields[0]);
                            fieldMap.put("rkl_ingestion_ts", Long.valueOf(fields[1]));
                            fieldMap.put("region_id", Integer.valueOf(fields[2]));
                            fieldMap.put("account_id", Integer.valueOf(fields[3]));
                            fieldMap.put("customer_id", Integer.valueOf(fields[4]));
                            fieldMap.put("observer_id", String.valueOf(fields[5]));
                            fieldMap.put("srcip", String.valueOf(InetAddresses.fromInteger(Integer.parseInt(fields[6])).getHostAddress()));
                            fieldMap.put("dstip", String.valueOf(InetAddresses.fromInteger(Integer.parseInt(fields[7])).getHostAddress()));
                            fieldMap.put("srcport", Integer.valueOf(fields[8]));
                            fieldMap.put("dstport", Integer.valueOf(fields[9]));
                            fieldMap.put("proto", Integer.valueOf(fields[10]));
                            fieldMap.put("pkt", Integer.valueOf(fields[11]));
                            fieldMap.put("bytes", Integer.valueOf(fields[12]));
                            fieldMap.put("to_time", Long.valueOf(fields[13]));
                            Boolean fa = Boolean.valueOf(fields[14]);
                            if (fa) {
                                fieldMap.put("firewall_action", "true");
                            } else {
                                fieldMap.put("firewall_action", false);
                            }
                            fieldMap.put("issrcpublic", Boolean.valueOf(fields[15]));
                            fieldMap.put("isdstpublic", Boolean.valueOf(fields[16]));
                            fieldMap.put("ts", Long.valueOf(fields[17]));
                            fieldMap.put("ingestionts", Long.valueOf(fields[18]));
                            fieldMap.put("conn_dir", Integer.valueOf(fields[19]));


                            bulkBuilder.add(client.prepareIndex(indexName, "flows", fields[0]).setSource(fieldMap));

                            ctr++;

                            if (ctr > flushEvery) {
                                logger.info("Starting to flush...");
                                long start = System.currentTimeMillis();
                                BulkResponse bulkRes = bulkBuilder.execute().actionGet();
                                long end = System.currentTimeMillis();
                                if (bulkRes.hasFailures()) {
                                    logger.error("Error in inserting");
                                }
                                logger.info("Flushed in seconds {}", (end - start) / 1000);
                                ctr = 0;
                            }

                        }
                        BulkResponse bulkRes = bulkBuilder.execute().actionGet();
                        if (bulkRes.hasFailures()) {
                            logger.error("Error in inserting");
                        }

                        fileInputStream.close();
                    } catch (Exception e) {
                        logger.error("Error: ", e);
                    }


                    submissionCounter[0]++;
                }
            });


        } catch (Exception e) {
            logger.error("Error: ", e);
        }


    }


}
