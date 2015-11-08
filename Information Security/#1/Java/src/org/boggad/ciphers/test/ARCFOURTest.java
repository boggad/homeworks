package org.boggad.ciphers.test;

import org.boggad.ciphers.ARCFOUR;

import java.util.Base64;
import java.util.Scanner;


public class ARCFOURTest {

    public static String byteToHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            builder.append(String.format("%02x", bytes[i]));
        }

        return builder.toString();
    }

    public static byte[] hexToByte(String hex) {
        char[] string = hex.toCharArray();
        byte[] result = new byte[string.length/2];
        int len = string.length;
        for(int i = 0; i < len; i += 2) {
            result[i/2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) +
                    Character.digit(hex.charAt(i+1), 16));
        }
        return result;
    }


    public static void main(String[] args) {
        int shaRounds = 0;
        boolean passFirstMb = false;
        for (String arg: args) {
            if (arg.length() < 5) continue;
            if ((arg.length() > 8) && arg.substring(0, 8).equals("-sha512=")) {
                shaRounds = Integer.parseInt(arg.substring(8));
            }
            if (arg.substring(0, 5).equals("-p1mb")) {
                passFirstMb = true;
            }
        }
        boolean ready = false;
        Scanner scanner = new Scanner(System.in);
        String mode = "";
        while (!ready) {
            System.out.print("Шифровать или дешифровать? (e/d): ");
            mode = scanner.next();

            if (mode.equals("x")) {
                return;
            }

            ready = mode.toLowerCase().equals("e") || mode.toLowerCase().equals("d");
        }

        scanner.nextLine();

        byte[] input;
        if (mode.equals("e")) {
            System.out.println("Введите сообщение: ");
            String msg = scanner.nextLine();
            input = msg.getBytes();
        } else {
            System.out.println("Введите зашифрованный текст (HEX): ");
            String msg = scanner.nextLine();
            input = hexToByte(msg);
        }

        System.out.println("Введите ключ: ");
        String key = scanner.nextLine();

        ARCFOUR rc4 = ARCFOUR.getInstance(key.getBytes());

        byte[] out = rc4.rc4(input, shaRounds, passFirstMb);

        if (mode.equals("e")) {
            System.out.println("Зашифрованный текст (HEX):");
            System.out.println(byteToHex(out));
            System.out.println("Зашифрованный текст (Base64):");
            System.out.println(new String(Base64.getEncoder().encode(out)));
        } else {
            System.out.println("Исходный текст:");
            System.out.println(new String(out));
        }
    }
}
