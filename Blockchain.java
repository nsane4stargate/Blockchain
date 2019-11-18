/*--------------------------------------------------------

1. Lea Middleton / 5.29.2019:

2. Java version used: Java 1.8.0_201

3. Precise command-line compilation examples / instructions:

> javac Blockchain.java

4. Precise examples / instructions to run this program:

In separate shell windows:

> java Blockchain

5. List of other files accompanied with MyWebServer.java.

 a. http-streams.txt
 b. serverlog.txt
 c. checklist-mywebserver.html

----------------------------------------------------------*/


import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.time.LocalDate;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;

public class Blockchain{

    private static int process_id;

    public static void main(String[] args){

        /* Get process id */
        if(args.length < 1){
            process_id = 0;
        }else{
            process_id = Integer.parseInt(args[0]);
        }
        try{
            System.out.println("Blockchain program running ");
            System.out.println("Current process id in use : " + process_id);
            BlockChainAUX blockchain = new BlockChainAUX(process_id);
            blockchain.run();
        }catch(Exception e){
            System.out.println("Couldn't establish blockchain " + e);
        }
    }
}
//////////////////////////////////////////* END of Blockchain class *///////////////////////////////////////////
//////////////////////////////////////////* START of BlockChainAUX class *////////////////////////////////////
class BlockChainAUX extends BlockChainBuilder {
    /* Assigning port numbers with variables */
    private static final int PUBLIC_KEY_PORT = 4710;
    private static final int UNVERIFIED_BLOCKS_PORT = 4820;
    static final int UPDATED_BLOCKCHAIN_PORT = 4930;

    private static int process_id; /* Place holder for process_id from main program entry */

    private static KeyPair key_pair; /* Place holder for encrypt and decrypt key pairs */
    private static PublicKeyServer public_key_server;
    private static UnverifiedBlockServer ublock_server;
    private static BlockChainServer bchain_server;
    private static Socket blockchain_socket;

    public BlockChainAUX(int process_id){
        super();
        /* Initialize process_id */
        BlockChainAUX.process_id = process_id;
        /* Generate keys pairs */
        key_pair = generateKeyPair();
        /////* Initialize servers */////
        initializeServers();
    }

    public void run() throws Exception {
        /////* Start servers */////
        startServers();
        /* Let threads sleep for 10 seconds */
        try{
            Thread.sleep(100);
        } catch (InterruptedException e) {
            System.out.println("BlockChainAUX run() method, thread was interrupted!");
        }
        /* Do work and verify blocks */
        new Thread(new UnverifiedBlockConsumer()).start();

        /* When P2 starts, it also triggers the multicast of public keys,
                                            and starts the whole system running */
        if(process_id == 2){
            /* Let current thread sleep */
            try{
                Thread.sleep(100);
            } catch (InterruptedException e) {
                System.out.println("BlockChainAUX run() method, thread was interrupted!");
            }
            blockchain_socket = new Socket();
            (new BroadCastMessage()).start();
        }
    }
    /* Initialization of servers utility */
    public void initializeServers(){
        this.public_key_server = new PublicKeyServer();
        this.ublock_server = new UnverifiedBlockServer();
        this.bchain_server = new BlockChainServer();
    }

    /* Servers starter utility */
    public void startServers(){
        (new Thread(public_key_server)).start();
        (new Thread(ublock_server)).start();
        (new Thread(bchain_server)).start();
    }

    public static int getProcessId(){return process_id;}
    public static int getPublicKeyPort(){return (PUBLIC_KEY_PORT + process_id);}
    public static int getUnverifiedBlocksPort(){return (UNVERIFIED_BLOCKS_PORT + process_id);}
    public static int getUpdatedBlockchainPort(){return (UPDATED_BLOCKCHAIN_PORT + process_id);}
    public static KeyPair getKey_pair(){return key_pair;}
    public static Socket getBlockChainSocket(){return blockchain_socket;}
}
///////////////////////////////////////////* END of BlockchainWorker class *////////////////////////////////////
//////////////////////////////////////////* START of BlockChainBuilder class *//////////////////////////////////
class BlockChainBuilder {
    private static HashMap<Integer, String> public_key_hash = new HashMap<>();
    private static JAXBContext jaxb_context;
    private static Unmarshaller jaxb_unmarshaller;
    private static StringReader reader;
    private static StringWriter string_writer;
    private static Marshaller jaxb_marshaller;
    private static List<BlockRecord> blockchain_list = Collections.synchronizedList(new ArrayList<BlockRecord>());
    private static List<BlockRecord> block_list;
    private static BlockingQueue<String> queue = new PriorityBlockingQueue<>();
    private static String block = "", refractor_block = "", xml = "", file_name, suuid, file_strings;
    private static BlockRecord block_record, block_inputs_record;
    private static final String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
    private static int iFNAME = 0, iLNAME = 1, iDOB = 2, iSSN = 3, iDIAG = 4, iTREAT = 5, iRX = 6, p_num;
    private static BufferedReader bufferedReader;
    private static String[] inputs;

    public BlockChainBuilder(){
    }

    /* Use Java class KeyPairGenerator to generate public and private keys */
    public KeyPair generateKeyPair(){
        KeyPair pair = null;
        try {
            /* KeyPairGenerator object */
            KeyPairGenerator keys = KeyPairGenerator.getInstance("RSA");
            /* Generate a random source and use as a parameter to generate keys */
            SecureRandom secure_random = SecureRandom.getInstance("SHA1PRNG","SUN");
            /* Set seed for SecureRandom object */
            secure_random.setSeed(LocalDate.now().toEpochDay());
            /* Initialize KeyPairGenerator object as a 1024 bit with secure_randomness */
            keys.initialize(1024,secure_random);
            /* Acquire keys */
            pair = keys.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Encryption algorithm does not exist\n");
        } catch (NoSuchProviderException e) {
            System.out.println("Secure random provider does not exist\n");
        }
        return pair;
    }

    /* Convert public key to base 64 */
    public static String conversion64(java.security.PublicKey aPublic) {
        String publicKeyBase64 = "";
        byte[] publicKeyEncoded = BlockChainAUX.getKey_pair().getPublic().getEncoded();
        publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyEncoded);

        return publicKeyBase64;
    }

    /* Decode base 64 public key */
    public static String getDecodedPublicKey(String key) {
        byte[] decodeData = Base64.getDecoder().decode(key);
        String decodedPublicKey = new String(decodeData);

        return decodedPublicKey;
    }

    /* Create unmarshallXML BlockRecord */
    public static BlockRecord xmlUnmarshall(String xml){
        try {
            jaxb_context = JAXBContext.newInstance(BlockRecord.class);
            jaxb_unmarshaller = jaxb_context.createUnmarshaller();
            reader = new StringReader(xml);
            block_record = (BlockRecord)jaxb_unmarshaller.unmarshal(reader);
        } catch (JAXBException e) {
            System.out.println("BlockChainBuilder xmlUnmarshall() method's could not un-marshal data");
        }
        return block_record;
    }

    /* Get blockchain XML string */
    public static String getXMLString(){
        try{
            jaxb_context = JAXBContext.newInstance(BlockRecord.class);
            jaxb_marshaller = jaxb_context.createMarshaller();
            string_writer = new StringWriter();
            jaxb_marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT,true);

            for(BlockRecord record : blockchain_list){
                jaxb_marshaller.marshal(record, string_writer);
            }

            block = string_writer.toString();
            refractor_block = block.replace(XMLHeader, "");
            xml = "\n<BlockLedger>" + refractor_block + "</BlockLedger>";
        } catch (JAXBException e) {
            System.out.println("BlockChainBuilder getXMLString() method's could not marshal data");
        }
        return xml;
    }

    public static String blockInput(String[] args){
        /* CDE If you want to trigger bragging rights functionality... */
        if (args.length > 1) System.out.println("Special functionality is present\n");

        if (args.length < 1) p_num = 0;
        else if (args[0].equals("0")) p_num = 0;
        else if (args[0].equals("1")) p_num = 1;
        else if (args[0].equals("2")) p_num = 2;
        else if (args[0].equals("3")) p_num = 3; // 3 for dummy block
        else p_num = 0; /* Default for badly formed argument */

        switch(p_num){
            case 1:
                file_name = "BlockInput1.txt";
                break;
            case 2:
                file_name = "BlockInput2.txt";
                break;
            case 3:
                file_name = "DummyBlock.txt";
                break;
            default:
                file_name = "BlockInput0.txt";
                break;
        }

        try {
            bufferedReader = new BufferedReader(new FileReader(System.getProperty("user.dir") + "/src/" + file_name));
            string_writer = new StringWriter();

            /* Make a new instance of block_list ArrayList to store marshalled blocks */
            block_list = new ArrayList<BlockRecord>();
            jaxb_context = JAXBContext.newInstance(BlockRecord.class);
            jaxb_marshaller = jaxb_context.createMarshaller();
            jaxb_marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

            /* Read data from file and add its input into a blockrecord then add it to the list of blockchains */
            while((file_strings = bufferedReader.readLine()) != null){
                createBlockfromInputs(file_strings);
            }

            /* Marshal the block */
            for(BlockRecord blockRecord : blockchain_list){
                jaxb_marshaller.marshal(blockRecord,string_writer);
            }
            block = string_writer.toString();
            refractor_block = block.replace(XMLHeader,"");
            xml = XMLHeader + "\n<BlockLedger>" + refractor_block + "</BlockLedger>";

        } catch (FileNotFoundException e) {
           System.out.println("BlockChainBuilder blockInput() method's BufferReader could not locate file\n");
        } catch (JAXBException e) {
            System.out.println("BlockChainBuilder blockInput() method's could not marshal data\n");
        } catch (IOException e) {
            System.out.println("BlockChainBuilder blockInput() method's variable file_strings is NULL\n");
        }
        return xml;
    }

    private static void createBlockfromInputs(String input_string){
        block_inputs_record = new BlockRecord();

        /* Set SHA256 string */
        block_inputs_record.setASHA256String("SHA string goes here...");
        block_inputs_record.setASignedSHA256("Signed SHA string goes here...");

        /* CDE: Generate a unique blockID. This would also be signed by creating process: */
        suuid = UUID.randomUUID().toString();
        block_inputs_record.setABlockID(suuid);
        block_inputs_record.setACreatingProcess("Process" + p_num);
        block_inputs_record.setAVerificationProcessID("To be set later...");

        /* CDE separate the file data into tokens and put into the block record: */
        inputs = input_string.split(" +");
        block_inputs_record.setSSN(inputs[iSSN]);
        block_inputs_record.setFNAME(inputs[iFNAME]);
        block_inputs_record.setLNAME(inputs[iLNAME]);
        block_inputs_record.setDOB(inputs[iDOB]);
        block_inputs_record.setDIAG(inputs[iDIAG]);
        block_inputs_record.setTREAT(inputs[iTREAT]);
        block_inputs_record.setRX(inputs[iRX]);

        /* Add newly created block_input_record to the list of block records */
        blockchain_list.add(block_inputs_record);
    }

    public static HashMap<Integer, String> getPublicKeyHashMap(){return public_key_hash;}

    public static List<BlockRecord> getBlockchainList(){return blockchain_list;}

    public static BlockingQueue<String> getQueue(){return queue;}

    public static Boolean idExist(String block_id){
        for(BlockRecord block_record: BlockChainBuilder.getBlockchainList()){
            if(block_record.getABlockID().contentEquals(block_id)){
                return true;
            }
        }
        return false;
    }
}
//////////////////////////////////////////* END of BlockChainBuilder class *////////////////////////////////////
//////////////////////////////////////////* START of SendKeyMessage class */////////////////////////////////////
class BroadCastMessage extends MulticastWorker {

    /* Constructor for BroadCastMessage */
    public BroadCastMessage() throws Exception{
        super(BlockChainAUX.getProcessId(), BlockChainAUX.getBlockChainSocket());
    }

    public void run (){
        /* Multicast message to all processes */
        try {
            multiCast();
        } catch (Exception e) {
        }
    }
}
//////////////////////////////////////////* END of SendKeyMessage class *///////////////////////////////////////
//////////////////////////////////////////* START of PublicKeyServer class *////////////////////////////////////
class PublicKeyServer implements Runnable{
    private static int process_id;
    private static Socket socket;
    private int port;
    private ServerSocket public_key_serversocket;

    public PublicKeyServer(){
        this.process_id = BlockChainAUX.getProcessId();
        this.port = BlockChainAUX.getPublicKeyPort();
    }

    @Override
    public void run() {

        System.out.println("Starting Public Key Server input thread using " + BlockChainAUX.getPublicKeyPort());

        /* Try to access Public Key ports */
        try{
            public_key_serversocket = new ServerSocket(port);
            /* Continue to listen for new clients and connect them to the server */
            while(true){
                socket = public_key_serversocket.accept();
                new PublicKeyWorker().start();
            }
        }catch(Exception e){
            System.out.println("Port " + port + " is currently in use!!");
        }
    }

    /* Method to access Public_Key initialized socket */
    public static Socket getPublicKeySocket(){return socket;}
    /* Method to access Public_Key process_id */
    public static int getPublicKeyProcessID(){return process_id;}
}
//////////////////////////////////////////* END of PublicKeyServer class *//////////////////////////////////////
//////////////////////////////////////////* START of PublicKeyWorker class *////////////////////////////////////
class PublicKeyWorker extends MulticastWorker {
    private BufferedReader in_from_client;
    private String[] inputs;
    private String message, public_key;
    private Integer PID;

    /* Initialize constructor */
    public PublicKeyWorker() throws Exception {
        super(PublicKeyServer.getPublicKeyProcessID(), PublicKeyServer.getPublicKeySocket());
    }

    public void run() {
        /* Get I/O streams in/out from the socket */
        try {
            in_from_client = new BufferedReader(new InputStreamReader(MulticastWorker.getIncomingSocket().getInputStream()));

            /* Read in the first line to see the message type */
            message = in_from_client.readLine();
            System.out.println("Got key: " + message + "\n");

            /* Store PublicKey and PID into the hashmap */
            storePublicKeyandPID();
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }

    /* Store PublicKey and PID into the hashmap */
    void storePublicKeyandPID(){
        System.out.println("In PublicKeyWorker, storePublicKeyandPID() method \n");
        inputs = message.split(" ");
        PID = Integer.parseInt(inputs[1]);
        BlockChainBuilder.getPublicKeyHashMap().put(PID, BlockChainBuilder.getDecodedPublicKey(inputs[9]));
    }
}
///////////////////////////////////////////* END of PublicKeyWorker class */////////////////////////////////////
//////////////////////////////////* START of UnverifiedBlockServer class *//////////////////////////////////////
class UnverifiedBlockServer implements Runnable{
    private static Socket ublock_socket;
    public ServerSocket ublock_serversocket;
    private int port;
    private static int process_id;

    /* UnverifiedBlockServer constructor */
    public UnverifiedBlockServer(){
        this.port = BlockChainAUX.getUnverifiedBlocksPort();
        this.process_id = BlockChainAUX.getProcessId();
    }

    @Override
    public void run() {
        try{
            ublock_serversocket = new ServerSocket(port);
        } catch (IOException e) {
            System.out.println("UnverifiedBlockServer run() method, port: " + port + " is already in use");
        }
        System.out.println("UnverifiedBlockServer for process: " + process_id + " up, listening at port: " + port);
        while(true){
            try{
                ublock_socket = ublock_serversocket.accept();
                new UnverifiedBlockWorker().start();
            } catch (IOException e) {
                System.out.println("UnverifiedBlockServer ublock_serversocket is already in use");
            }
        }
    }
    /* Return UnverifiedBlockServer socket */
    public static Socket getUnverifiedBlockSocket(){return ublock_socket;}
    /* Return UnverifiedBlockServer process_id */
    public static int getUnverifiedProcessID(){return process_id;}
}
//////////////////////////////////////////* END of UnverifiedBlockServer class *////////////////////////////////
//////////////////////////////////////////* START of UnverifiedBlockWorker class *//////////////////////////////
class UnverifiedBlockWorker extends MulticastWorker {
    private BufferedReader in_from_server;
    private String message = "";
    private StringBuilder str_builder;
    private List<String> strings_for_blocks = new ArrayList<>();

    /* UnverifiedBlockWorker Constructor */
    public UnverifiedBlockWorker() {
        super(UnverifiedBlockServer.getUnverifiedProcessID(), UnverifiedBlockServer.getUnverifiedBlockSocket());
    }

    public void run() {
        try {
            in_from_server = new BufferedReader(new InputStreamReader(getIncomingSocket().getInputStream()));
            str_builder = new StringBuilder();

            /* Continue to read data from file and add to list of blockchain_string and BlockingQueue */
            while ((message = in_from_server.readLine()) != null) {
                setBlockingQueue(message);
            }

            for(String strings : strings_for_blocks){
                BlockChainBuilder.getQueue().put(strings);
            }

            /* Close current socket instance */
            getIncomingSocket().close();
        } catch (IOException e) {
            System.out.println("UnverifiedBlockWorker in_from_server cannot BufferRead from socket");
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void setBlockingQueue(String message) {
        if (!(message.equals("<BlockLedger>") || message.equals("</BlockLedger") || message.equals("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>")))
            str_builder.append(message);
        if (message.equals("</blockRecord>")) {
            strings_for_blocks.add(str_builder.toString());
            str_builder.delete(0, str_builder.length());
        }
    }
}
//////////////////////////////////////////* END of UnverifiedBlockWorker class *////////////////////////////////
//////////////////////////////////////* START of UnverifiedBlockConsumer class *////////////////////////////////
class UnverifiedBlockConsumer implements Runnable{
    private String block_record_data, block_verified_string;
    private PrintStream out_to_server;
    private Socket ubconsumer_socket;
    private int port;
    private String[] data_records_strings;
    private BlockRecord block_record;

    public UnverifiedBlockConsumer(){}

    @Override
    public void run() {
        System.out.println("Running the UnverifiedBlockConsumer class. \n");
        try{
            while(true){
                if(!BlockChainBuilder.getQueue().isEmpty()) {
                    block_record_data = BlockChainBuilder.getQueue().take(); /* Will block-wait on empty queue */
                    System.out.println("Consumer got unverified: \n" + block_record_data + "\n");
                    verifyAndWork();
                }
            }
        } catch (InterruptedException e) {
            System.out.println("UnverifiedBlockConsumer run() method blocking queue was interrupted");
        }
    }

    public void verifyAndWork(){
        try{
            /* Assign BlockRecord variable to unmarshalled XML string data */
            block_record = BlockChainBuilder.xmlUnmarshall(block_record_data);

            ///* Work algorithm *///
            int j; // Here we fake doing some work (That is, here we could cheat, so not ACTUAL work...)
            for(int i=0; i< 100; i++){ // put a limit on the fake work for this example
                j = ThreadLocalRandom.current().nextInt(0,10);
                try{Thread.sleep(500);
                }catch(Exception e){
                    e.printStackTrace();
                }
                if (j < 3) break; // <- how hard our fake work is; about 1.5 seconds.
            }

            /* Check to see if id already exist in the List of blockchains.
               If it doesn't, add it to the List of blockchains */
            if (!BlockChainBuilder.idExist(block_record.getABlockID())) {
                block_record.setAVerificationProcessID(String.valueOf(BlockChainAUX.getProcessId()));
                if (BlockChainBuilder.getBlockchainList().size() > 0) {
                    block_record.setPreviousHash(BlockChainBuilder.getBlockchainList().get(BlockChainBuilder.getBlockchainList().size() - 1).getABlockID());
                }

                /* Add verified block to the chain */
                BlockChainBuilder.getBlockchainList().add(block_record);
                block_verified_string = BlockChainBuilder.getXMLString();

                for(int z=0; z < 3; z++) {
                    /* Send to each process in group, including us: */
                    port = BlockChainAUX.UPDATED_BLOCKCHAIN_PORT + z;
                    try {
                        ubconsumer_socket = new Socket("localhost", port);
                        System.out.println("UnverifiedBlockServer for process: " + BlockChainAUX.getProcessId() + " up, listening at port: " + port);
                    } catch (IOException e) {
                        System.out.println("In UnverifiedBlockConsumer in work() method, ubconsumer_socket could not connect" +
                                "Port: " + port + " is currently being used !!");
                    }
                    try {
                        out_to_server = new PrintStream(ubconsumer_socket.getOutputStream());
                    } catch (IOException e) {
                        System.out.println("In UnverifiedBlockConsumer in work() method, out_of_server could not establish PrintStream()");
                    }
                    out_to_server.println(block_verified_string);
                    out_to_server.flush(); // make the multicast
                    try {
                        ubconsumer_socket.close();
                    } catch (IOException e) {
                        System.out.println("In UnverifiedBlockConsumer in work() method, ubconsumer_socket is already closed. Cannot complete command");
                    }
                }
                Thread.sleep(1000); // For the example, wait for our blockchain to be updated before processing a new block
            }
        } catch (InterruptedException e) {
           System.out.println("In UnverifiedBlockConsumer in work() method, thread is currently sleeping !!!");
        }
    }
}
//////////////////////////////////////////* END of UnverifiedBlockConsumer class *//////////////////////////////
//////////////////////////////////////////* START of BlockchainServer class *///////////////////////////////////
class BlockChainServer implements Runnable{
    private static int process_id;
    private int port;
    private static Socket blockchain_socket;
    private ServerSocket bc_serversocket;

    public BlockChainServer(){
        this.process_id = BlockChainAUX.getProcessId();
        this.port = BlockChainAUX.getUpdatedBlockchainPort();
    }

    @Override
    public void run() {
        try{
            bc_serversocket = new ServerSocket(port);
            System.out.println
                    ("\nBlockchainServer listening at port: " + port + " process_id: " + process_id + "\n");
        } catch (IOException e) {
            System.out.println("Blockchain bc_serversocket could not connect. Port: " + port + " is already in use!!");
        }
        while(true) {
            try {
                blockchain_socket = bc_serversocket.accept();
                new BlockChainWorker().start();
                System.out.println("BlockchainServer connected sucessfully!!!\n");
            } catch (IOException a) {
                System.out.println("Blockchain blockchain_socket could not connect. Server connection already established");
            }
        }
    }

    public static Socket getBlockchainSocket(){return blockchain_socket;}
    public static int getBlockchainProcessID(){return process_id;}
}
//////////////////////////////////////////* END of BlockchainServer class */////////////////////////////////////
//////////////////////////////////////////* START of BlockchainWorker class *///////////////////////////////////
class BlockChainWorker extends MulticastWorker{
    private BufferedReader in_from_server;
    private String data, data_for_block = "", new_block_string;
    private String[] seperated_strings;
    private BlockRecord new_block_record;
    private final String block_format = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";

    public BlockChainWorker(){
        super(BlockChainServer.getBlockchainProcessID(), BlockChainServer.getBlockchainSocket());
    }

    public void run(){
        try{
            in_from_server = new BufferedReader(new InputStreamReader(getIncomingSocket().getInputStream()));
            while((data = in_from_server.readLine())!= null){
                data_for_block += data;
            }
            data_for_block = data_for_block.replace(block_format, "");
            seperated_strings = data_for_block.split("<blockRecord");

            if(BlockChainBuilder.getBlockchainList().size() >= seperated_strings.length - 1){
                return;
            }
            /* Build list of Blockchain */
            buildBlockChainList();

            /* Close current connection */
            getIncomingSocket().close();
        } catch (IOException e) {
            System.out.println("BlockchainWorker in_from_server cannot BufferRead from socket");
        }
    }

    public void buildBlockChainList(){
        BlockChainBuilder.getBlockchainList().clear();
        /* Create a new block and add it to the list of other blockchains */
        for(int i = 1; i <seperated_strings.length; i ++){
            new_block_string = ("<blockRecord>" + seperated_strings[i]).replace("</BlockLedger>", "");
            new_block_record = (BlockRecord) BlockChainBuilder.xmlUnmarshall(new_block_string);
            BlockChainBuilder.getBlockchainList().add(new_block_record);
        }
        /* Print out blockChainList */
        System.out.println("BlockChain List:");
        System.out.println(BlockChainBuilder.getXMLString() + "\n");
    }
}
//////////////////////////////////////////* END of BlockchainWorker class */////////////////////////////////////
////////////////////////////////////////* START of MulticastWorker class *//////////////////////////////////////
class MulticastWorker extends Thread {
    private int port, unverified_block_port, increment = 0, process_id;
    private Socket public_key_socket, unverified_block_socket;
    private static Socket incoming_socket;
    private PrintStream out_to_server = null;
    private String public_key, message, XMLblock;
    private String[] file = new String[1];
    private boolean dummy_block_sent = false;

    public MulticastWorker(int process_id, Socket socket) {
        this.process_id = process_id;
        incoming_socket = socket;
    }

    public void multiCast()throws Exception {
        /* Use all ports assigned for Public Key server */
        while (increment < 3) {
            port = (BlockChainAUX.getPublicKeyPort() - BlockChainAUX.getProcessId()) + increment;
            System.out.println("Port " + port + " is currently being used \n");

            /* Listen for new client connections */
            try {
                public_key_socket = new Socket("localhost", port);
                out_to_server = new PrintStream(public_key_socket.getOutputStream());
                /* Convert public key to 64 base */
                public_key = BlockChainAUX.conversion64(BlockChainAUX.getKey_pair().getPublic());
                message = "Port " + port + " using process_ id " + BlockChainAUX.getProcessId() + " with Public key: " + public_key;
                /* Send a message to client indicating what port, process_id, and public key currently being used */
                out_to_server.println(message);
                public_key_socket.close();
            } catch (IOException e) {
                System.out.println("Could not connect!!! Port " + port + " is currently being used!!\n");
            }
            increment++;
        }
        increment = 0;
        Thread.sleep(1000);
        if (!dummy_block_sent){
            sendUnverifiedBlock(String.valueOf(3));
            dummy_block_sent = true;
        }
        Thread.sleep(1000);
        sendUnverifiedBlock(String.valueOf(BlockChainAUX.getProcessId()));
        dummy_block_sent = false;
    }

    /* Send unverified blocks to server */
    void sendUnverifiedBlock(String value) throws Exception{
        port = BlockChainAUX.getUnverifiedBlocksPort() - BlockChainAUX.getProcessId();
        file[0] = value;
        XMLblock = BlockChainBuilder.blockInput(file);

        for (int i = 0; i < 3; i++) {
            unverified_block_port = port + i;
            System.out.println(" Current port being sent unverified block is: " +unverified_block_port + "\n");

            unverified_block_socket = new Socket("localhost",unverified_block_port);
            out_to_server = new PrintStream(unverified_block_socket.getOutputStream());
            /* Send unverified block to server */
            out_to_server.println(XMLblock);
            /* Flush out Printstream */
            out_to_server.flush();
            unverified_block_socket.close();
        }
    }

    /* Return incoming_socket */
    public static Socket getIncomingSocket() {
        return incoming_socket;
    }
}
/////////////////////////////////////* END of MulticastWorker class *///////////////////////////////////////////
////////////////////////////////////////* START of BlockRecord class *//////////////////////////////////////////
@XmlRootElement
class BlockRecord {
    /* Examples of block fields: */
    private String SHA256String;
    private String SignedSHA256;
    private String BlockID;
    private String VerificationProcessID;
    private String CreatingProcess;
    private String PreviousHash;
    private String Fname;
    private String Lname;
    private String SSNum;
    private String DOB;
    private String Diag;
    private String Treat;
    private String Rx;

      /* Examples of accessors for the BlockRecord fields. Note that the XML tools sort the fields alphabetically
     by name of accessors, so A=header, F=Indentification, G=Medical: */

    public String getASHA256String() {return SHA256String;}
    @XmlElement
    public void setASHA256String(String SH){this.SHA256String = SH;}

    public String getASignedSHA256() {return SignedSHA256;}
    @XmlElement
    public void setASignedSHA256(String SH){this.SignedSHA256 = SH;}

    public String getACreatingProcess() {return CreatingProcess;}
    @XmlElement
    public void setACreatingProcess(String CP){this.CreatingProcess = CP;}

    public String getAVerificationProcessID() {return VerificationProcessID;}
    @XmlElement
    public void setAVerificationProcessID(String VID){this.VerificationProcessID = VID;}

    public String getABlockID() {return BlockID;}
    @XmlElement
    public void setABlockID(String BID){this.BlockID = BID;}

    public String getPreviousHash() {return PreviousHash;}
    @XmlElement
    public void setPreviousHash(String prevHash){this.PreviousHash = prevHash;}

    public String getSSN() {return SSNum;}
    @XmlElement
    public void setSSN(String SS){this.SSNum = SS;}

    public String getFNAME() {return Fname;}
    @XmlElement
    public void setFNAME(String FN){this.Fname = FN;}

    public String getLNAME() {return Lname;}
    @XmlElement
    public void setLNAME(String LN){this.Lname = LN;}

    public String getDOB() {return DOB;}
    @XmlElement
    public void setDOB(String DOB){this.DOB = DOB;}

    public String getDIAG() {return Diag;}
    @XmlElement
    public void setDIAG(String D){this.Diag = D;}

    public String getTREAT() {return Treat;}
    @XmlElement
    public void setTREAT(String D){this.Treat = D;}

    public String getRX() {return Rx;}
    @XmlElement
    public void setRX(String D){this.Rx = D;}
}
////////////////////////////////////////* END of BlockRecord class *////////////////////////////////////////////
