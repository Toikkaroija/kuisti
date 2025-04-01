# Kuisti
Kuisti is an experimental system that aims to utilize physical identifiers and elements for implicit authentication to create a multifactor authentication process for workstation logons and network access. The goal is to use existing systems (physical access control, work-time monitoring, tracking systems (RTLS), etc.) to verify users' presence before allowing them to logon to workstations and access networked resources.

More in-depth documentation will be moved and created here when I get to it.

Currently all the existing comments etc. in the source files are in Finnish, and they will be translated into English later on.

## How Are Physical Elements Used for Workstation MFA and NAC?

Essentially, Kuisti's aim is to connect external systems that are based on physical identifiers and elements (e.g. physical access control), local directory servers and firewalls together to create an MFA-process for workstation logons and allow access to networked resources only when a user is considered to be present. In summary, the logon process proceeds as follows:
1. User identifies himself/herself using a physical identifier or an element, when entering an area.
2. Kuisti notes the user's presence and allows logon to workstations within that area.
3. When the user logs on to a workstation, Kuisti creates necessary firewall rules for the user to access resources.
4. When the user logs out and leaves the area, Kuisti deletes the firewall rules and blocks logon to workstations within that area.

In short terms, the idea is to limit implicit access to workstations and networked resources, when access in not needed.

## Before Installation
Kuisti controls local workstation logons by managing roomgroups on a directory server via LDAPS. Each roomgroup is linked to a physical room or an area within the environment. This way logons to workstations within an area are allowed, if a user is a member of the roomgroup linked to the area in question.

To achieve such functionality, you need to create the following things on your directory server:
1. Roomgroup(s) for each physical area in your environment;
2. Policies to restrict workstation logons for only roomgroup members; and
3. A service account called "kuisti" to manage roomgroup memberships.

Necessary GPOs for restricting local logons can be found in the examples/ad/gpos-folder.
Also note that Kuisti needs access to modify the memberships of these groups, so be sure to allow Kuisti's service account read and write access to those groups.


## Installation

The installation is divided into two parts: Server and plugin installation. The server program has been developed and tested only on Ubuntu 22.04.3 LTS, so the installation script is intended for Debian based systems.
The plugins are meant to be installed on logging servers, that can forward workstation logon/logoff/lock/unlock events to Kuisti for MFA and NAC purposes. Currently, only WEC servers (Windows Event Collector) are supported.

### Server Installation

1. Clone the repository.
   ```bash
   git clone https://github.com/Toikkaroija/kuisti.git
   ```
2. Run the installation script.
   ```bash
   chmod +x install.sh && ./install.sh
   ```

### Plugin Installation
#### For Windows AD and WEC

1. Verify, that you have performed the preinstallation procedures listed under section "Before Installation".
2. Create a GPO for logon/logoff/lock/unlock event collection and prevent the use of cached credentials (see examples/ad/gpos/Kuisti_SecuritySettings.jpg)
3. Create a GPO for enforcing screensaver usage to distinguish manual locking from automatic locking due to inactivity (see examples/ad/gpos/Kuisti_Screensaver.jpg)
4. Create a GPO for WEF (see examples/ad/gpos/Kuisti_WEF.jpg)
5. Copy the ADPlugin-folder from the repository to your AD-server, which has WEC installed.
6. Add Kuisti's service account to the Event Log Readers group.
7. Allow the service account to run batch jobs using the server's secpol or GPO.
8. Run the following command as an administrator inside the ADPlugin folder:
   ```powershell
   .\Install-KuistiADPlugin -serviceUserName SERVICE_USER -logName LOG_NAME -remoteEndpointIpAddress KUISTI_IP -remoteEndpointPort KUISTI_PORT
   ```
   Substitute all arguments written in uppercase with the appropiate values for your environment. By default, WEC uses "ForwardedEvents" for log collection.
9. Reboot the server.
   

## Configuration

The kuisti/confs folder has some example confiurations which can be used as templates. Better instructions on configurations are coming soon(-ish).
