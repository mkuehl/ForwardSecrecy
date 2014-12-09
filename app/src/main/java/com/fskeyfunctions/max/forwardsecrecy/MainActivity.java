package com.fskeyfunctions.max.forwardsecrecy;

import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.view.Menu;
import android.view.MenuItem;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Locale;

import javax.crypto.KeyAgreement;


public class MainActivity extends ActionBarActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        String language = Locale.getDefault().getLanguage();

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    /**
     * Simulates an elliptic curve Diffie-Hellman key exchange.
     * Found on http://www.java2s.com/Tutorial/Java/0490__Security/DiffieHellmanwithEllipticCurve.htm
     */
    private static void ecdh() {
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());

        KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance("ECDH", "BC");

            //predefined curves: P-256, P-384 and P-521
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-521");

            keyGen.initialize(ecSpec, new SecureRandom());

            KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
            KeyPair aPair = keyGen.generateKeyPair();
            KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
            KeyPair bPair = keyGen.generateKeyPair();

            aKeyAgree.init(aPair.getPrivate());
            bKeyAgree.init(bPair.getPrivate());

            aKeyAgree.doPhase(bPair.getPublic(), true);
            bKeyAgree.doPhase(aPair.getPublic(), true);

            MessageDigest hash = MessageDigest.getInstance("SHA1");

            byte[] aByteSec = aKeyAgree.generateSecret(),
                    bByteSec = bKeyAgree.generateSecret();
            String aSecret = new String(hash.digest(aKeyAgree.generateSecret())),
                    bSecret = new String(hash.digest(bKeyAgree.generateSecret()));
            System.out.println(aSecret);
            System.out.println(bSecret);
            System.out.println("Alice: " + Arrays.toString(aByteSec) + "\nBob: " + Arrays.toString(bByteSec));
            System.out.println(MessageDigest.isEqual(aByteSec, bByteSec));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalArgumentException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
