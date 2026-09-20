package app.veil.vpn;

import android.app.*;
import android.content.Intent;
import com.wireguard.android.backend.GoBackend;

public final class ShieldVpnService extends GoBackend.VpnService {
    @Override public void onCreate(){
        super.onCreate();
        NotificationManager manager=getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel("vpn","VPN connection",NotificationManager.IMPORTANCE_LOW));
        PendingIntent open=PendingIntent.getActivity(this,0,new Intent(this,MainActivity.class),PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop=PendingIntent.getService(this,1,new Intent(this,ShieldVpnService.class).setAction("STOP"),PendingIntent.FLAG_IMMUTABLE);
        Notification n=new Notification.Builder(this,"vpn").setSmallIcon(R.drawable.shield).setContentTitle("Veil VPN")
            .setContentText("VPN service running. Open Veil to check the handshake.").setContentIntent(open).setOngoing(true)
            .addAction(new Notification.Action.Builder(null,"Disconnect",stop).build()).build();
        startForeground(1,n);
    }
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        super.onStartCommand(intent,flags,startId);
        TunnelController c=TunnelController.get(this);
        if(intent!=null&&"STOP".equals(intent.getAction()))c.disconnect();else c.connect(this);
        return START_STICKY;
    }
    @Override public void onRevoke(){stopSelf();}
    @Override public void onDestroy(){super.onDestroy();TunnelController.get(this).stopped(this);}
}
