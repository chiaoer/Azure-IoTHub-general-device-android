package com.iothub.azure.microsoft.com.synnexapp;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.StatFs;
import android.provider.Settings;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.EditText;

import com.microsoft.azure.sdk.iot.device.ClientOptions;
import com.microsoft.azure.sdk.iot.device.DeviceClient;
import com.microsoft.azure.sdk.iot.device.DeviceTwin.DeviceMethodData;
import com.microsoft.azure.sdk.iot.device.DeviceTwin.Pair;
import com.microsoft.azure.sdk.iot.device.DeviceTwin.Property;
import com.microsoft.azure.sdk.iot.device.DeviceTwin.TwinPropertyCallBack;
import com.microsoft.azure.sdk.iot.device.IotHubClientProtocol;
import com.microsoft.azure.sdk.iot.device.IotHubEventCallback;
import com.microsoft.azure.sdk.iot.device.IotHubMessageResult;
import com.microsoft.azure.sdk.iot.device.IotHubStatusCode;
import com.microsoft.azure.sdk.iot.device.Message;
import com.microsoft.azure.sdk.iot.provisioning.device.AdditionalData;
import com.microsoft.azure.sdk.iot.provisioning.device.ProvisioningDeviceClient;
import com.microsoft.azure.sdk.iot.provisioning.device.ProvisioningDeviceClientRegistrationCallback;
import com.microsoft.azure.sdk.iot.provisioning.device.ProvisioningDeviceClientRegistrationResult;
import com.microsoft.azure.sdk.iot.provisioning.device.ProvisioningDeviceClientStatus;
import com.microsoft.azure.sdk.iot.provisioning.device.ProvisioningDeviceClientTransportProtocol;
import com.microsoft.azure.sdk.iot.provisioning.device.internal.exceptions.ProvisioningDeviceClientException;
import com.microsoft.azure.sdk.iot.provisioning.security.SecurityProviderSymmetricKey;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

import static org.apache.commons.lang3.StringUtils.capitalize;

public class MainActivity extends AppCompatActivity {

    private enum LIGHTS{ ON, OFF, DISABLED }

    private enum CAMERA{ DETECTED_BURGLAR, SAFELY_WORKING }

    private static final int MAX_EVENTS_TO_REPORT = 5;

    // DTDL interface used: https://github.com/Azure/iot-plugandplay-models/blob/main/dtmi/com/example/thermostat-1.json
    private static final String connString = "[Enter your connection string here]";
    private static final String deviceSecurityType = "DPS";
    //private static final String deviceSecurityType = "connectionstring";
    private static final String modelId = "[Enter your device model ID here]";

    // Environmental variables for Dps
    private static final String scopeId = "[Your scope ID here]"; //online test
    // Typically "global.azure-devices-provisioning.net"
    private static final String globalEndpoint = "[Your Provisioning Service Global Endpoint here]";
    private static final String deviceSymmetricKey = "[Enter your Symmetric Key here]"; //online test
    private static final String registrationId = "[Enter your Registration ID here]";//online test

    private static final ProvisioningDeviceClientTransportProtocol provisioningProtocol = ProvisioningDeviceClientTransportProtocol.MQTT;
    private static final int MAX_TIME_TO_WAIT_FOR_REGISTRATION = 1000; // in milli seconds

    private static DeviceClient client;

    IotHubClientProtocol protocol = IotHubClientProtocol.MQTT;
    Context appContext;

    private static final int METHOD_SUCCESS = 200;
    private static final int METHOD_NOT_DEFINED = 404;

    private String hostname;
    private String cpuInfo;
    private long cpuCores;
    private long cpuMaxfreq;
    private String baseboardManufacturer;
    private String baseboardSerialNumber;
    private String osVersion;
    private String osBuildNumber;
    private long memTotal;
    private long logicalDISKtotal;
    private String ipLocal;
    private String ipPublic;
    private double highTemp;
    private double currentTempGPU;
    private double cpuClock;
    private long memFree;
    private long memUsage;
    private long logicalDISKfree;
    private long logicalDISKusage;
    private double currentTemp;

    private static final String publicKeyCertificateString = "";

    //PEM encoded representation of the private key
    private static final String privateKeyString = "";

    private String getHostname() {
        return Settings.Global.getString(getApplicationContext().getContentResolver(), Settings.Global.DEVICE_NAME);
    }

    private String getManufacturer() {
        return Build.MANUFACTURER;
    }

    private String getModel() {
        return Build.MODEL;
    }

    @NotNull
    @Contract(pure = true)
    private String getAndroidVersion() {
        return "android" + Build.VERSION.RELEASE;
    }

    @NotNull
    private String getAndroidBuildNumber() {
        return Integer.toString(Build.VERSION.SDK_INT);
    }

    private String getCPUInfo() {
        String str, output = "Unavailable";
        BufferedReader br;

        try {
            br = new BufferedReader(new FileReader("/proc/cpuinfo"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return "Unavailable";
        }

        try{
            while((str = br.readLine()) != null) {
                String[] data = str.split(":");
                if (data.length > 1) {
                    String key = data[0].trim().replace(" ", "_");
                    if (key.equals("Hardware") || key.equals("model_name")) {
                        output = data[1].trim();
                    }
                }
            }
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return output;
    }

/*    private int getNumCoresOldPhones() {
        //Private Class to display only CPU devices in the directory listing
        class CpuFilter implements FileFilter {
            @Override
            public boolean accept(@NotNull File pathname) {
                //Check if filename is "cpu", followed by a single digit number
                return Pattern.matches("cpu[0-9]+", pathname.getName());
            }
        }

        try {
            // Get directory containing CPU info
            File dir = new File("/sys/devices/system/cpu/");
            //Filter to only list the devices we care about
            File[] files = dir.listFiles(new CpuFilter());
            //Return the number of cores (virtual CPU devices)
            if (files != null) {
                return files.length;
            }
        } catch(Exception e) {
            //Default to return 1 core
            return 1;
        }
        return 1;
    }*/

    private long getNumberOfCores() {
        return Runtime.getRuntime().availableProcessors();
    }

    private long getCPUMaxFreq() {
        BufferedReader reader;

        try {
            reader = new BufferedReader(new FileReader("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return 0;
        }

        try {
            String cpuMaxFreq = reader.readLine();
            reader.close();
            return Long.parseLong(cpuMaxFreq) / 1000000L;
        } catch (IOException e) {
            e.printStackTrace();
            return 0;
        }
    }

    private long getMEMTotal() {
        ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
        ActivityManager activityManager = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
        activityManager.getMemoryInfo(mi);

        return mi.totalMem / 0x100000L;
    }

    private long getTotalDiskSpace() {
        StatFs statFs = new StatFs(Environment.getRootDirectory().getAbsolutePath());
        long rootDiskSpace = statFs.getBlockCountLong() * statFs.getBlockSizeLong();
        statFs = new StatFs(Environment.getDataDirectory().getAbsolutePath());
        long dataDiskSpace = statFs.getBlockCountLong() * statFs.getBlockSizeLong();

        return (rootDiskSpace + dataDiskSpace) / 0x100000L;
    }

    private String getLocalIpAddress() {
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements();) {
                NetworkInterface intf = en.nextElement();
                for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements();) {
                    InetAddress inetAddress = enumIpAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress() && inetAddress instanceof Inet4Address) {
                        return inetAddress.getHostAddress();
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
            return "Unavailable";
        }

        return "Unavailable";
    }

    private String getPublicIPAddress() {
        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<String> result = es.submit(new Callable<String>() {
            public String call() throws Exception {
                try {
                    URL url = new URL("http://whatismyip.akamai.com/");
                    HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
                    try {
                        InputStream in = new BufferedInputStream(urlConnection.getInputStream());
                        BufferedReader r = new BufferedReader(new InputStreamReader(in));
                        StringBuilder total = new StringBuilder();
                        String line;
                        while ((line = r.readLine()) != null) {
                            total.append(line).append('\n');
                        }
                        urlConnection.disconnect();
                        return total.toString();
                    }finally {
                        urlConnection.disconnect();
                    }
                }catch (IOException e){
                    Log.e("Public IP: ",e.getMessage());
                }
                return "Unavailable";
            }
        });

        try {
            return result.get();
        } catch (Exception e) {
            e.printStackTrace();
            return "Unavailable";
        }
    }

    private double getCpuTemp() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/sys/devices/virtual/thermal/thermal_zone0/temp"));
            String cputemp = reader.readLine();
            reader.close();
            return Double.parseDouble(cputemp) / 1000;
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    private double getGpuTemp() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/sys/class/thermal/thermal_zone10/temp"));
            String gputemp = reader.readLine();
            reader.close();
            return Double.parseDouble(gputemp) / 1000;
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    private double getCPUFreq() {
        BufferedReader reader;

        try {
            reader = new BufferedReader(new FileReader("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return 0;
        }

        try {
            String cpuFreq = reader.readLine();
            reader.close();
            return Double.parseDouble(cpuFreq) / 1000000;
        } catch (IOException e) {
            e.printStackTrace();
            return 0;
        }
    }

    private long getMEMavail() {
        ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
        ActivityManager activityManager = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
        activityManager.getMemoryInfo(mi);

        return mi.availMem / 0x100000L;
    }

    private long getMEMusage() {
        return getMEMTotal() - getMEMavail();
    }

    private long freeDISK()
    {
        StatFs statFs = new StatFs(Environment.getRootDirectory().getAbsolutePath());
        long freeRoot = (statFs.getAvailableBlocksLong() * statFs.getBlockSizeLong());
        statFs = new StatFs(Environment.getDataDirectory().getAbsolutePath());
        long freeData = statFs.getAvailableBlocksLong() * statFs.getBlockSizeLong();

        return (freeRoot + freeData) / 0x100000L;
    }

    private long busyDISK()
    {
        return getTotalDiskSpace() - freeDISK();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            InitClient();
        } catch (Exception e2)
        {
            System.out.println("Exception while opening IoTHub connection: " + e2.toString());
        }
    }

    private static boolean validateArgsForDpsFlow()
    {
        return !((globalEndpoint == null || globalEndpoint.isEmpty())
                && (scopeId == null || scopeId.isEmpty())
                && (registrationId == null || registrationId.isEmpty())
                && (deviceSymmetricKey == null || deviceSymmetricKey.isEmpty()));
    }

    private static boolean validateArgsForIotHubFlow()
    {
        return !(connString == null || connString.isEmpty());
    }

    static class ProvisioningStatus
    {
        ProvisioningDeviceClientRegistrationResult provisioningDeviceClientRegistrationInfoClient = new ProvisioningDeviceClientRegistrationResult();
        Exception exception;
    }

    static class ProvisioningDeviceClientRegistrationCallbackImpl implements ProvisioningDeviceClientRegistrationCallback
    {
        @Override
        public void run(ProvisioningDeviceClientRegistrationResult provisioningDeviceClientRegistrationResult, Exception exception, Object context)
        {
            if (context instanceof ProvisioningStatus)
            {
                ProvisioningStatus status = (ProvisioningStatus) context;
                status.provisioningDeviceClientRegistrationInfoClient = provisioningDeviceClientRegistrationResult;
                status.exception = exception;
            }
            else
            {
                System.out.println("Received unknown context");
            }
        }
    }

    private static void initializeAndProvisionDevice() throws ProvisioningDeviceClientException, IOException, URISyntaxException, InterruptedException {
        SecurityProviderSymmetricKey securityClientSymmetricKey = new SecurityProviderSymmetricKey(deviceSymmetricKey.getBytes(), registrationId);
        ProvisioningDeviceClient provisioningDeviceClient = null;
        ProvisioningStatus provisioningStatus = new ProvisioningStatus();

        provisioningDeviceClient = ProvisioningDeviceClient.create(globalEndpoint, scopeId, provisioningProtocol, securityClientSymmetricKey);

        AdditionalData additionalData = new AdditionalData();
        additionalData.setProvisioningPayload(String.format("{\"modelId\": \"%s\"}", modelId));

        provisioningDeviceClient.registerDevice(new ProvisioningDeviceClientRegistrationCallbackImpl(), provisioningStatus, additionalData);

        while (provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getProvisioningDeviceClientStatus() != ProvisioningDeviceClientStatus.PROVISIONING_DEVICE_STATUS_ASSIGNED)
        {
            if (provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getProvisioningDeviceClientStatus() == ProvisioningDeviceClientStatus.PROVISIONING_DEVICE_STATUS_ERROR ||
                    provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getProvisioningDeviceClientStatus() == ProvisioningDeviceClientStatus.PROVISIONING_DEVICE_STATUS_DISABLED ||
                    provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getProvisioningDeviceClientStatus() == ProvisioningDeviceClientStatus.PROVISIONING_DEVICE_STATUS_FAILED)
            {
                provisioningStatus.exception.printStackTrace();
                System.out.println("Registration error, bailing out");
                break;
            }
            System.out.println("Waiting for Provisioning Service to register");
            Thread.sleep(MAX_TIME_TO_WAIT_FOR_REGISTRATION);
        }

        ClientOptions options = new ClientOptions();
        options.setModelId(modelId);

        if (provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getProvisioningDeviceClientStatus() == ProvisioningDeviceClientStatus.PROVISIONING_DEVICE_STATUS_ASSIGNED) {
            System.out.println("IotHUb Uri : " + provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getIothubUri());
            System.out.println("Device ID : " + provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getDeviceId());

            String iotHubUri = provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getIothubUri();
            String deviceId = provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getDeviceId();

            System.out.println("Opening the device client.");
            client = DeviceClient.createFromSecurityProvider(iotHubUri, deviceId, securityClientSymmetricKey, IotHubClientProtocol.MQTT, options);
        }
    }

    private static int method_command(Object command)
    {
        System.out.println("invoking command on this device");
        // Insert code to invoke command here
        return METHOD_SUCCESS;
    }

    private static int method_default(Object data)
    {
        System.out.println("invoking default method for this device");
        // Insert device specific code here
        return METHOD_NOT_DEFINED;
    }

    protected static class DeviceMethodStatusCallBack implements IotHubEventCallback
    {
        public void execute(IotHubStatusCode status, Object context)
        {
            System.out.println("IoT Hub responded to device method operation with status " + status.name());
        }
    }

    protected static class SampleDeviceMethodCallback implements com.microsoft.azure.sdk.iot.device.DeviceTwin.DeviceMethodCallback
    {
        @Override
        public DeviceMethodData call(String methodName, Object methodData, Object context)
        {
            DeviceMethodData deviceMethodData ;
            switch (methodName)
            {
                case "command" :
                {
                    int status = method_command(methodData);

                    deviceMethodData = new DeviceMethodData(status, "executed " + methodName);
                    break;
                }
                default:
                {
                    int status = method_default(methodData);
                    deviceMethodData = new DeviceMethodData(status, "executed " + methodName);
                }
            }

            return deviceMethodData;
        }
    }

    private static final AtomicBoolean Succeed = new AtomicBoolean(false);

    protected static class DeviceTwinStatusCallBack implements IotHubEventCallback
    {
        @Override
        public void execute(IotHubStatusCode status, Object context)
        {
            Succeed.set((status == IotHubStatusCode.OK) || (status == IotHubStatusCode.OK_EMPTY));
            System.out.println("IoT Hub responded to device twin operation with status " + status.name());
        }
    }

    protected static class onProperty implements TwinPropertyCallBack
    {
        @Override
        public void TwinPropertyCallBack(Property property, Object context)
        {
            System.out.println(
                    "onProperty callback for " + (property.getIsReported()?"reported": "desired") +
                            " property " + property.getKey() +
                            " to " + property.getValue() +
                            ", Properties version:" + property.getVersion());
        }
    }

    private void InitClient() throws URISyntaxException, IOException, ProvisioningDeviceClientException, InterruptedException
    {
        hostname = getHostname();
        cpuInfo = getCPUInfo();
        cpuCores = getNumberOfCores();
        cpuMaxfreq = getCPUMaxFreq();
        baseboardManufacturer = getManufacturer();
        baseboardSerialNumber = getModel();
        osVersion = getAndroidVersion();
        osBuildNumber = getAndroidBuildNumber();
        memTotal = getMEMTotal();
        logicalDISKtotal = getTotalDiskSpace();
        ipLocal = getLocalIpAddress();
        ipPublic = getPublicIPAddress();
        highTemp = getCpuTemp();
        currentTempGPU = getGpuTemp();
        cpuClock = getCPUFreq();
        memFree = getMEMavail();
        memUsage = getMEMusage();
        logicalDISKfree = freeDISK();
        logicalDISKusage = busyDISK();
        currentTemp = getCpuTemp();

        System.out.println("Property dump...");
        System.out.println("hostname = " + hostname);
        System.out.println("cpuInfo = " + cpuInfo);
        System.out.println("cpuCores = " + cpuCores);
        System.out.println("cpuMaxfreq = " + cpuMaxfreq + "GHz");
        System.out.println("baseboardManufacturer = " + baseboardManufacturer);
        System.out.println("baseboardSerialNumber = " + baseboardSerialNumber);
        System.out.println("osVersion = " + osVersion);
        System.out.println("osBuildNumber = " + osBuildNumber);
        System.out.println("memTotal = " + memTotal + "MB");
        System.out.println("logicalDISKtotal = " + logicalDISKtotal + "MB");
        System.out.println("ipLocal = " + ipLocal);
        System.out.println("ipPublic = " + ipPublic);
        System.out.println("highTemp = " + highTemp);
        System.out.println("currentTempGPU = " + currentTempGPU);
        System.out.println("cpuClock = " + cpuClock);
        System.out.println("memFree = " + memFree + "MB");
        System.out.println("memUsage = " + memUsage + "MB");
        System.out.println("logicalDISKfree = " + logicalDISKfree + "MB");
        System.out.println("logicalDISKusage = " + logicalDISKusage + "MB");
        System.out.println("currentTemp = " + currentTemp);

        if ((deviceSecurityType == null) || deviceSecurityType.isEmpty())
        {
            throw new IllegalArgumentException("Device security type needs to be specified, please set the environment variable \"IOTHUB_DEVICE_SECURITY_TYPE\"");
        }

        System.out.println("Initialize the device client.");

        switch (deviceSecurityType.toLowerCase()) {
            case "dps": {
                if (validateArgsForDpsFlow()) {
                    initializeAndProvisionDevice();
                    break;
                }
                throw new IllegalArgumentException("Required environment variables are not set for DPS flow, please recheck your environment.");
            }
            case "connectionstring": {
                if (validateArgsForIotHubFlow()) {
                    client = new DeviceClient(connString, protocol);
                    break;
                }
                throw new IllegalArgumentException("Required environment variables are not set for IoT Hub flow, please recheck your environment.");
            }
            default: {
                throw new IllegalArgumentException("Unrecognized value for IOTHUB_DEVICE_SECURITY_TYPE received: {s_deviceSecurityType}." +
                        " It should be either \"DPS\" or \"connectionString\" (case-insensitive).");
            }
        }

        try
        {
            client.open();
            if (protocol == IotHubClientProtocol.MQTT)
            {
                MessageCallbackMqtt callback = new MessageCallbackMqtt();
                Counter counter = new Counter(0);
                client.setMessageCallback(callback, counter);
            } else
            {
                MessageCallback callback = new MessageCallback();
                Counter counter = new Counter(0);
                client.setMessageCallback(callback, counter);
            }
            client.subscribeToDeviceMethod(new SampleDeviceMethodCallback(), null, new DeviceMethodStatusCallBack(), null);
            Succeed.set(false);
            client.startDeviceTwin(new DeviceTwinStatusCallBack(), null, new onProperty(), null);

            do
            {
                Thread.sleep(1000);
            }
            while(!Succeed.get());

            Map<Property, Pair<TwinPropertyCallBack, Object>> desiredProperties = new HashMap<Property, Pair<TwinPropertyCallBack, Object>>()
            {
                {
                    put(new Property("hostname", null), new Pair<TwinPropertyCallBack, Object>(new onProperty(), null));
                    put(new Property("cpuInfo", null), new Pair<TwinPropertyCallBack, Object>(new onProperty(), null));
                    put(new Property("cpuCores", null), new Pair<TwinPropertyCallBack, Object>(new onProperty(), null));
                    put(new Property("cpuMaxfreq", null), new Pair<TwinPropertyCallBack, Object>(new onProperty(), null));
                    put(new Property("baseboardManufacturer", null), new Pair<TwinPropertyCallBack, Object>(new onProperty(), null));
                    put(new Property("baseboardSerialNumber", null), new Pair<TwinPropertyCallBack, Object>(new onProperty(), null));
                    put(new Property("osVersion", null), new Pair<TwinPropertyCallBack, Object>(new onProperty(), null));
                    put(new Property("osBuildNumber", null), new Pair<TwinPropertyCallBack, Object>(new onProperty(), null));
                    put(new Property("memTotal", null), new Pair<TwinPropertyCallBack, Object>(new onProperty(), null));
                    put(new Property("logicalDISKtotal", null), new Pair<TwinPropertyCallBack, Object>(new onProperty(), null));
                    put(new Property("ipLocal", null), new Pair<TwinPropertyCallBack, Object>(new onProperty(), null));
                    put(new Property("ipPublic", null), new Pair<TwinPropertyCallBack, Object>(new onProperty(), null));
                    put(new Property("highTemp", null), new Pair<TwinPropertyCallBack, Object>(new onProperty(), null));
                }
            };

            client.subscribeToTwinDesiredProperties(desiredProperties);

            System.out.println("Subscribe to Desired properties on device Twin...");
        }
        catch (Exception e2)
        {
            System.err.println("Exception while opening IoTHub connection: " + e2.getMessage());
            client.closeNow();
            System.out.println("Shutting down...");
        }
    }

    public void btnGetTwinOnClick(View v) throws URISyntaxException, IOException
    {
        System.out.println("Get device Twin...");
        client.getDeviceTwin(); // For each desired property in the Service, the SDK will call the appropriate callback with the value and version.
    }

    public void btnUpdateReportedOnClick(View v) throws URISyntaxException, IOException
    {
            System.out.println("Update reported properties...");

            String componentName = "AndroidDeviceInfo1";
            Set<Property> reportProperties = PnpConvention.createComponentPropertyPatch(componentName, new HashMap<String, Object>()
            {{
                put("hostname", hostname);
                put("cpuInfo", cpuInfo);
                put("cpuCores", cpuCores);
                put("cpuMaxfreq", cpuMaxfreq);
                put("baseboardManufacturer", baseboardManufacturer);
                put("baseboardSerialNumber", baseboardSerialNumber);
                put("osVersion", osVersion);
                put("osBuildNumber", osBuildNumber);
                put("memTotal", memTotal);
                put("logicalDISKtotal", logicalDISKtotal);
                put("ipLocal", ipLocal);
                put("ipPublic", ipPublic);
                put("highTemp", highTemp);
            }});

//            Set<Property> reportProperties = new HashSet<Property>()
//            {
//                {
//                    add(new Property("hostname", hostname));
//                    add(new Property("cpuInfo", cpuInfo));
//                    add(new Property("cpuCores", cpuCores));
//                    add(new Property("cpuMaxfreq", cpuMaxfreq));
//                    add(new Property("baseboardManufacturer", baseboardManufacturer));
//                    add(new Property("baseboardSerialNumber", baseboardSerialNumber));
//                    add(new Property("osVersion", osVersion));
//                    add(new Property("osBuildNumber", osBuildNumber));
//                    add(new Property("memTotal", memTotal));
//                    add(new Property("logicalDISKtotal", logicalDISKtotal));
//                    add(new Property("ipLocal", ipLocal));
//                    add(new Property("ipPublic", ipPublic));
//                    add(new Property("highTemp", highTemp));
//                }
//            };
            client.sendReportedProperties(reportProperties);

        for(int i = 0; i < MAX_EVENTS_TO_REPORT; i++)
        {

            if (Math.random() % MAX_EVENTS_TO_REPORT == 3)
            {
                client.sendReportedProperties(new HashSet<Property>() {{ add(new Property("HomeSecurityCamera", CAMERA.DETECTED_BURGLAR)); }});
            }
            else
            {
                client.sendReportedProperties(new HashSet<Property>() {{ add(new Property("HomeSecurityCamera", CAMERA.SAFELY_WORKING)); }});
            }
            if(i == MAX_EVENTS_TO_REPORT-1)
            {
                client.sendReportedProperties(new HashSet<Property>() {{ add(new Property("BedroomRoomLights", null)); }});
            }
            System.out.println("Updating reported properties..");
        }

        System.out.println("Waiting for Desired properties");
    }

    public void btnSendOnClick(View v) throws URISyntaxException, IOException
    {
        String componentName = "AndroidDeviceInfo1";
        String TELEMETRY_COMPONENT_NAME = "$.sub";

        currentTempGPU = getGpuTemp();
        cpuClock = getCPUFreq();
        memFree = getMEMavail();
        memUsage = getMEMusage();
        logicalDISKfree = freeDISK();
        logicalDISKusage = busyDISK();
        currentTemp = getCpuTemp();

//        String msgStr = "{\"currentTempGPU\":\"" + currentTempGPU + "\",\"cpuClock\":" + cpuClock + "\",\"memFree\":" + memFree + "\",\"memUsage\":" + memUsage;
//        msgStr += ",\"logicalDISKfree\":" + logicalDISKfree + ",\"logicalDISKusage\":" + logicalDISKusage + ",\"currentTemp\":" + currentTemp + "}";
        String msgStr = "{\"currentTempGPU\":" + currentTempGPU + ",\"cpuClock\":" + cpuClock + ",\"memFree\":" + memFree + ",\"memUsage\":" + memUsage;
        msgStr += ",\"logicalDISKfree\":" + logicalDISKfree + ",\"logicalDISKusage\":" + logicalDISKusage + ",\"currentTemp\":" + currentTemp + "}";

        try
        {
            Message msg = new Message(msgStr);
            msg.setMessageId(java.util.UUID.randomUUID().toString());
            if (componentName != null) {
                msg.setProperty(TELEMETRY_COMPONENT_NAME, componentName);
            }
            System.out.println(msgStr);
            EventCallback eventCallback = new EventCallback();
                client.sendEventAsync(msg, eventCallback, 1);
        }
        catch (Exception e)
        {
            System.err.println("Exception while sending event: " + e.getMessage());
        }
    }

    public void btnFileUploadOnClick(View v) throws URISyntaxException, IOException
    {
        EditText text = (EditText)findViewById(R.id.editTextFileName);
        String fullFileName = text.getText().toString();

        try
        {
            Context context = getApplicationContext();

            File directory = context.getFilesDir();
            File file = new File(directory, fullFileName);
            file.createNewFile();
            if(file.isDirectory())
            {
                throw new IllegalArgumentException(fullFileName + " is a directory, please provide a single file name, or use the FileUploadSample to upload directories.");
            }
            else
            {
                client.uploadToBlobAsync(file.getName(), new FileInputStream(file), file.length(), new FileUploadStatusCallBack(), null);
            }

            System.out.println("File upload started with success");

            System.out.println("Waiting for file upload callback with the status...");
        }
        catch (Exception e)
        {
            System.err.println("Exception while sending event: " + e.getMessage());
        }
    }

    protected static class FileUploadStatusCallBack implements IotHubEventCallback
    {
        public void execute(IotHubStatusCode status, Object context)
        {
            System.out.println("IoT Hub responded to file upload operation with status " + status.name());
        }
    }

    private void stopClient() throws URISyntaxException, IOException
    {
        String OPERATING_SYSTEM = System.getProperty("os.name");
        client.closeNow();
        System.out.println("Shutting down..." + OPERATING_SYSTEM);
        android.os.Process.killProcess(android.os.Process.myPid());
    }

    public void btnStopOnClick(View v) throws URISyntaxException, IOException
    {
        stopClient();
    }

    // Our MQTT doesn't support abandon/reject, so we will only display the messaged received
    // from IoTHub and return COMPLETE
    static class MessageCallbackMqtt implements com.microsoft.azure.sdk.iot.device.MessageCallback
    {
        public IotHubMessageResult execute(Message msg, Object context)
        {
            Counter counter = (Counter) context;
            System.out.println(
                    "Received message " + counter.toString()
                            + " with content: " + new String(msg.getBytes(), Message.DEFAULT_IOTHUB_MESSAGE_CHARSET));

            counter.increment();

            return IotHubMessageResult.COMPLETE;
        }
    }

    static class EventCallback implements IotHubEventCallback
    {
        public void execute(IotHubStatusCode status, Object context)
        {
            Integer i = (Integer) context;
            System.out.println("IoT Hub responded to message " + i.toString()
                    + " with status " + status.name());
        }
    }

    static class MessageCallback implements com.microsoft.azure.sdk.iot.device.MessageCallback
    {
        public IotHubMessageResult execute(Message msg, Object context)
        {
            Counter counter = (Counter) context;
            System.out.println(
                    "Received message " + counter.toString()
                            + " with content: " + new String(msg.getBytes(), Message.DEFAULT_IOTHUB_MESSAGE_CHARSET));

            int switchVal = counter.get() % 3;
            IotHubMessageResult res;
            switch (switchVal)
            {
                case 0:
                    res = IotHubMessageResult.COMPLETE;
                    break;
                case 1:
                    res = IotHubMessageResult.ABANDON;
                    break;
                case 2:
                    res = IotHubMessageResult.REJECT;
                    break;
                default:
                    // should never happen.
                    throw new IllegalStateException("Invalid message result specified.");
            }

            System.out.println("Responding to message " + counter.toString() + " with " + res.name());

            counter.increment();

            return res;
        }
    }

    /**
     * Used as a counter in the message callback.
     */
    static class Counter
    {
        int num;

        Counter(int num) {
            this.num = num;
        }

        int get() {
            return this.num;
        }

        void increment() {
            this.num++;
        }

        @Override
        public String toString() {
            return Integer.toString(this.num);
        }
    }

}
