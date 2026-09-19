package ai.jevguard;
import android.content.Context;
import android.security.keystore.*;
import android.util.Base64;
import java.security.KeyStore;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
final class SecretStore {
 private final Context c;
 SecretStore(Context c){this.c=c;}
 private javax.crypto.SecretKey key() throws Exception {
  KeyStore s=KeyStore.getInstance("AndroidKeyStore");s.load(null);
  if(!s.containsAlias("jevguard.keys")) {
   KeyGenerator g=KeyGenerator.getInstance("AES","AndroidKeyStore");
   g.init(new KeyGenParameterSpec.Builder("jevguard.keys",KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build());g.generateKey();
  }
  return (javax.crypto.SecretKey)s.getKey("jevguard.keys",null);
 }
 void put(String name,String value)throws Exception {
  if(value.isEmpty()){c.getSharedPreferences("keys",0).edit().remove(name).commit();return;}
  Cipher x=Cipher.getInstance("AES/GCM/NoPadding");x.init(Cipher.ENCRYPT_MODE,key());
  String out=Base64.encodeToString(x.getIV(),Base64.NO_WRAP)+":"+Base64.encodeToString(x.doFinal(value.getBytes("UTF-8")),Base64.NO_WRAP);
  if(!c.getSharedPreferences("keys",0).edit().putString(name,out).commit())throw new Exception("Could not save key");
 }
 String get(String name)throws Exception {
  String v=c.getSharedPreferences("keys",0).getString(name,"");if(v.isEmpty())return "";
  String[] a=v.split(":");Cipher x=Cipher.getInstance("AES/GCM/NoPadding");x.init(Cipher.DECRYPT_MODE,key(),new GCMParameterSpec(128,Base64.decode(a[0],Base64.NO_WRAP)));
  return new String(x.doFinal(Base64.decode(a[1],Base64.NO_WRAP)),"UTF-8");
 }
}
