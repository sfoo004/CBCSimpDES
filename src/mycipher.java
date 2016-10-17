
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class mycipher {

    //Holds array positions permutations
    static int[] P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
    static int[] P8 = {6, 3, 7, 4, 8, 5, 10, 9};
    static int[] P4 = {2, 4, 3, 1};
    static int[] IP = {2, 6, 3, 1, 4, 8, 5, 7};
    static int[] IPINVERSE = {4, 1, 3, 5, 7, 2, 8, 6};
    static int[] EP = {4, 1, 2, 3, 2, 3, 4, 1};
    //holds keys
    static byte[] K1 = new byte[8];
    static byte[] K2 = new byte[8];
    //s values
    static String[][] S0 = {{"01", "00", "11", "10"},
    {"11", "10", "01", "00"},
    {"00", "10", "01", "11"},
    {"11", "01", "11", "10"}};
    static String[][] S1 = {{"00", "01", "10", "11"},
    {"10", "00", "01", "11"},
    {"11", "00", "01", "00"},
    {"10", "01", "00", "11"}};
    //encrpt or decrpyt file
    static boolean encrypt = false;
    static boolean invalid = false;
    static String fileRead;
    static String fileWrite;
    static int EXIT;
    static byte[] intVector = new byte[8];
    static byte[] binaryKey = new byte[8];

    public static void main(String[] args) {
        run(args);
        start();

    }

    //breaks down arguements to determine keys, IV, and where to read/write files
    public static void run(String[] args) {
        intVector = new byte[8];
        binaryKey = new byte[8];
  
        if (args.length != 10) {
            invalid = true;
            System.out.println("Invalid Arguements");
            System.exit(0);
        } else {
            for(int i = 0; i < args.length ; i++){
                if (args[i].equals("-m")) {
                    if (args[1].equals("encrypt")) {
                        encrypt = true;
                    } else {
                        encrypt = false;
                    }
                } else if (args[i].equals("-k")) {
                    binaryKey = convertToByteArr(args[3]);
                } else if (args[i].equals("-i")) {
                    intVector = convertToByteArr(args[5]);
                } else if (args[i].equals("-p")) {
                    if (encrypt) {
                        fileRead = args[7];
                    } else {
                        fileWrite = args[7];
                    }
                } else if (args[i].equals("-c")) {
                    if (encrypt) {
                        fileWrite = args[9];
                    } else {
                        fileRead = args[9];
                    }
                } else {
                    continue;
                }
            }
        }
    }

    /**
     * reads the file and puts them in p
     */
    private static void start() {
        List <String> hold = new ArrayList<>();
        try {
            BufferedReader in = new BufferedReader(new FileReader(fileRead));
            String lines = "";
            while ((lines = in.readLine()) != null) {
                String[] arr = lines.split(" ");
                for (String text : arr) {
                    hold.add(text);
                }

            }
            byte[][] p = new byte[hold.size()][8];
            EXIT = hold.size();
            for(int i = 0; i < EXIT ; i++){
                p[i] = convertToByteArr(hold.get(i));
            }
            CBC(intVector, binaryKey, p);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(mycipher.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(mycipher.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Prints the array bytes;
     * @param arr byte[]
     */
    private static void printArr(byte[] arr) {
        for (byte b : arr) {
            System.out.print(b);
        }
    }

    private static void CBC(byte[] intVec, byte[] binKey, byte[][] plainText) {
        boolean first = true;
        int xor;
        //holds the xor Vector for next cipher block
        byte[] xorVec = new byte[8];
        byte[] xorArr = new byte[8];
        //holds output from each cipher
        byte[][] output = new byte[EXIT][8];
        //Generates the keys for simp Des
        keyGen(binKey);
        if (encrypt) {
            for (int i = 0; i < EXIT; i++) {
                //first CBC will use the initial Vector
                if (first) {
                    first = false;
                    xor = (convertToInt(plainText[i]) ^ convertToInt(intVec));
                    xorArr = convertToByteArr(xor, 8);
                    xorVec = simpleDES(xorArr);
                    output[i] = xorVec;
                //will use the previous xorVector or plainText as XOR
                } else {
                    xor = (convertToInt(plainText[i]) ^ convertToInt(xorVec));
                    xorArr = convertToByteArr(xor, 8);
                    xorVec = simpleDES(xorArr);
                    output[i] = xorVec;

                }
            }
            printToFile(output, plainText);
        //decrypt
        } else {
            for (int i = 0; i < EXIT; i++) {
                //first CBC will use the initial Vector
                if (first) {
                    first = false;
                    xorArr = simpleDES(plainText[i]);
                    xor = (convertToInt(xorArr) ^ convertToInt(intVec));
                    xorVec = convertToByteArr(xor, 8);
                    output[i] = xorVec;
                    //will use the previous xorVector or plainText as XOR
                } else {
                    xorArr = simpleDES(plainText[i]);
                    xor = (convertToInt(xorArr) ^ convertToInt(plainText[i - 1]));
                    xorVec = convertToByteArr(xor, 8);
                    output[i] = xorVec;
                }
            }
            printToFile(output, plainText);
        }
    }

    /**
     * Will run the simple DES and give run different protocols if its encryption or decryption
     * @param xor byte []
     * @return 
     */
    private static byte[] simpleDES(byte[] xor) {
        byte[] temp = new byte[8];
        byte[] swap = new byte[8];
        byte[] cipher = new byte[8];
        //plaintext -> encryption
        if (encrypt) {
            for (int i = 0; i < xor.length; i++) {
                temp[i] = xor[IP[i] - 1];
            }
            //run fk with K1
            swap = fk(temp, K1);
            //swap first 4 with back 4
            temp = new byte[]{swap[4], swap[5], swap[6], swap[7], swap[0], swap[1], swap[2], swap[3]};
            //run fk with K2
            swap = fk(temp, K2);
            for (int i = 0; i < swap.length; i++) {
                cipher[i] = swap[IPINVERSE[i] - 1];
            }
            return cipher;
        //encryption -> plaintext
        } else {
            for (int i = 0; i < xor.length; i++) {
                temp[i] = xor[IP[i] - 1];
            }
            //run fk with K2
            swap = fk(temp, K2);
            //swap first 4 with back 4
            temp = new byte[]{swap[4], swap[5], swap[6], swap[7], swap[0], swap[1], swap[2], swap[3]};
            //run fk with K1
            swap = fk(temp, K1);
            for (int i = 0; i < swap.length; i++) {
                cipher[i] = swap[IPINVERSE[i] - 1];
            }
            return cipher;
        }

    }

    /**
     * runs the fk protocol in simple DES
     * @param input byte []
     * @param k byte []
     * @return 
     */
    private static byte[] fk(byte[] input, byte[] k) {
        byte[][] half = splitArr(input);
        byte[] whole = new byte[8];
        byte[] p4 = new byte[4];
        int xor;
        byte[] xorArr = new byte[4];
        //get new half from f process
        byte[] newHalf = f(half[1], k);
        for (int i = 0; i < 4; i++) {
            p4[i] = newHalf[P4[i] - 1];
        }
        //xor from first half and f 
        xor = convertToInt(half[0]) ^ convertToInt(p4);
        xorArr = convertToByteArr(xor, 4);
        //combine the xor half with the second half of the original
        for (int i = 0; i < whole.length; i++) {
            if (i < 4) {
                whole[i] = xorArr[i];
            } else {
                whole[i] = half[1][i - 4];
            }
        }
        return whole;
    }

    /**
     * Runs the f protocol in simple DES
     * @param half byte []
     * @param k byte []
     * @return byte []
     */
    private static byte[] f(byte[] half, byte[] k) {
        byte[] ep = new byte[8];
        int xor;
        int row;
        int col;
        String s0s1 = "";
        for (int i = 0; i < ep.length; i++) {
            ep[i] = half[EP[i] - 1];
        }
        xor = convertToInt(ep) ^ convertToInt(k);
        //split array
        byte[][] xorArr = splitArr(convertToByteArr(xor, 8));
        //determine S0 and S1 from grid
        row = convertToInt(new byte[]{xorArr[0][0], xorArr[0][3]});
        col = convertToInt(new byte[]{xorArr[0][1], xorArr[0][2]});
        s0s1 += S0[row][col];
        row = convertToInt(new byte[]{xorArr[1][0], xorArr[1][3]});
        col = convertToInt(new byte[]{xorArr[1][1], xorArr[1][2]});
        s0s1 += S1[row][col];

        return convertToByteArr(s0s1);

    }

    /**
     * generates K1 and K2
     * @param binKey byte []
     */
    private static void keyGen(byte[] binKey) {
        byte[] p10 = new byte[10];
        for (int i = 0; i < P10.length; i++) {
            p10[i] = binKey[P10[i] - 1];
        }
        //split array in half
        byte[][] half = splitArr(p10);

        half[0] = shift(half[0], 1);
        half[1] = shift(half[1], 1);

        K1 = getKey(half[0], half[1]);

        half[0] = shift(half[0], 2);
        half[1] = shift(half[1], 2);

        K2 = getKey(half[0], half[1]);

    }

    /**
     * Shifts based on move
     * @param arr byte []
     * @param move in
     * @return byte []
     */
    private static byte[] shift(byte[] arr, int move) {
        byte[] buffer = new byte[2];
        byte[] temp = new byte[5];
        if (move == 1) {
            buffer[0] = arr[0];
            temp = shiftLeft(arr);
            temp[4] = buffer[0];
            return temp;

        } else {
            buffer[0] = arr[0];
            buffer[1] = arr[1];
            temp = shiftLeft(arr);
            temp = shiftLeft(temp);
            temp[3] = buffer[0];
            temp[4] = buffer[1];
            return temp;
        }
    }

    /**
     * Left shift all the bytes
     * @param arr byte []
     * @return byte []
     */
    private static byte[] shiftLeft(byte[] arr) {
        byte[] temp = arr;
        for (int i = 0; i < arr.length - 1; i++) {
            temp[i] = arr[i + 1];
        }
        return temp;
    }

    /**
     * return p8 version of the key from p10
     * @param firstHalf byte []
     * @param secondHalf byte []
     * @return byte []
     */
    private static byte[] getKey(byte[] firstHalf, byte[] secondHalf) {
        byte[] p10 = new byte[10];
        byte[] p8 = new byte[8];
        for (int i = 0; i < p10.length; i++) {
            if (i <= 4) {
                p10[i] = firstHalf[i];
            } else {
                p10[i] = secondHalf[i - 5];
            }
        }

        for (int i = 0; i < p8.length; i++) {
            p8[i] = p10[P8[i] - 1];
        }

        return p8;
    }

    /**
     * Splits any byte array into two even halves and sends the halves back
     * @param arr byte [][]
     * @return 
     */
    private static byte[][] splitArr(byte[] arr) {
        byte[] firstHalf = new byte[arr.length / 2];
        byte[] secondHalf = new byte[arr.length / 2];
        for (int i = 0; i < arr.length / 2; i++) {
            firstHalf[i] = arr[i];
        }

        for (int i = 0; i < arr.length / 2; i++) {
            secondHalf[i] = arr[i + arr.length / 2];
        }

        return new byte[][]{firstHalf, secondHalf};

    }

    /**
     * convert String to byte Array
     * @param s
     * @return 
     */
    private static byte[] convertToByteArr(String s) {
        String[] raw = s.split("");
        byte[] conversion = new byte[raw.length];
        for (int i = 0; i < raw.length; i++) {
            conversion[i] = Byte.parseByte(raw[i]);
        }
        return conversion;
    }

    /**
     * Converts Integer to byte array
     * @param x Integer
     * @param size Integer
     * @return 
     */
    private static byte[] convertToByteArr(int x, int size) {
        int sum = x;
        int power = size - 1;
        byte[] arr = new byte[size];
        for (int i = 0; i < size; i++) {
            if (sum / Math.pow(2, power) >= 1) {
                arr[i] = 1;
                sum -= Math.pow(2, power--);
            } else {
                power--;
            }
        }
        return arr;
    }

    /**
     * Converts Byte array to a integer value
     * @param byteArr
     * @return 
     */
    private static int convertToInt(byte[] byteArr) {
        int power = byteArr.length - 1;
        int sum = 0;
        for (Byte b : byteArr) {
            if (b == 1) {
                sum += Math.pow(2, power--);
            } else {
                power--;
            }
        }
        return sum;
    }

    /**
     * prints to console and to files
     * @param ouput byte []
     * @param plainText byte []
     */
    private static void printToFile(byte[][] ouput, byte[][] plainText) {
        System.out.print("K1=");
        printArr(K1);
        System.out.println();
        System.out.print("K2=");
        printArr(K2);
        System.out.println();
        if(encrypt){
            System.out.print("plainText=");
            for(int i = 0; i < EXIT; i++){
                printArr(plainText[i]);
                System.out.print(" ");
            }
            System.out.println();  
            System.out.print("cipherText=");
            for(int i = 0; i < EXIT; i++){
                printArr(ouput[i]);
                System.out.print(" ");
            }
            System.out.println();
        } else {
            System.out.print("cipherText=");
            for(int i = 0; i < EXIT; i++){
                printArr(plainText[i]);
                System.out.print(" ");
            }
            System.out.println();  
            System.out.print("plainText=");
            for(int i = 0; i < EXIT; i++){
                printArr(ouput[i]);
                System.out.print(" ");
            }
            System.out.println();
        
        }
        
        File file = new File(fileWrite);
        FileWriter fw;
        try {
            fw = new FileWriter(file.getAbsoluteFile());
            BufferedWriter bw = new BufferedWriter(fw);
            for(int i = 0; i < ouput.length; i++){
                String bits = "";
                for(Byte b: ouput[i]){
                    bits+=b;
                }
                bw.write(bits + " ");
            }
            bw.close();
        } catch (IOException ex) {
            Logger.getLogger(mycipher.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
