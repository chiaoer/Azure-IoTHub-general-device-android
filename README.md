# Azure-IoTHub-general-device-android
This is a java code that makes you get system information and get current CPU/Memory/Storage usage and sent these data via Azure IoT Hub using Azure Device Provisioning Service. 
You can monitor your device's status remotely by Azure IoT Services.
#### To pass the Azure PnP Certification
Please fill the form to let us know, we will contact you as soon as possible.
[LINK to the Form](https://forms.office.com/Pages/ResponsePage.aspx?id=qRDzO7AbAkmVLXiwXlxBKh-utkxs0ltAnLVjtpzQ7mJUNzM4RUxWUlFWOEROQTVNTUFRN01FQ0Q5ViQlQCN0PWcu)
## About Azure IoT PnP in this project
IoT Plug and Play enables solution builders to integrate smart devices with their solutions without any manual configuration. At the core of IoT Plug and Play, is a device model that a device uses to advertise its capabilities to an IoT Plug and Play-enabled application. This project uses [androiddeviceinfo-1](https://github.com/Azure/iot-plugandplay-models/blob/main/dtmi/synnex/androiddeviceinfo-1.json) as device model. 
Support following elements:
| | Element Type | Data Type |
| ------ | ------ | ------ |
| hostname | Property | String | YES | YES |
| cpuInfo | Property | String | YES | YES |
|cpuCores | Property | long | YES | YES | 
| cpuMaxfreq | Property | double | YES | YES | 
| baseboardManufacturer | Property | String | YES | YES |
| baseboardSerialNumber | Property | String | YES | YES |
| osVersion | Property | String | YES | YES |
| osBuildNumber | Property | String | YES | YES | 
| memTotal | Property | long | YES | YES |
| logicalDISKtotal | Property | long | YES | YES |
| ipLocal | Property | String | YES | YES | 
| ipPublic | Property | String | YES | YES |
| highTemp | Property | double | YES | |
| currentTempGPU | Telemetry | double | YES (ARM SoC) | |
| cpuClock | Telemetry | double | YES | YES | 
| memFree | Telemetry | long | YES | YES | 
| memUsage | Telemetry | double | YES | YES |
| logicalDISKfree | Telemetry | long | YES | YES |
| logicalDISKusage | Telemetry | double | YES | YES |
| currentTemp | Telemetry | double | YES | |
