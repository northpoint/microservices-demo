# Copied from gatekeeper repo
# pod-security-policies

Kind / Constraint Name for querying statuses quickly:

K8sPSPAllowPrivilegeEscalationContainer psp-allow-privilege-escalation-container
K8sPSPAppArmor psp-apparmor
K8sPSPCapabilities psp-capabilities
K8sPSPFlexVolumes psp-flexvolume-drivers
K8sPSPFSGroup psp-fsgroup
K8sPSPHostFilesystem psp-host-filesystem
K8sPSPHostNamespace psp-host-namespace
K8sPSPHostNetworkingPorts psp-host-network-ports
K8sPSPPrivilegedContainer psp-privileged-container
K8sPSPProcMount psp-proc-mount
K8sPSPReadOnlyRootFilesystem psp-readonlyrootfilesystem
K8sPSPForbiddenSysctls psp-forbidden-sysctls
K8sPSPSeccomp psp-seccomp
K8sPSPSELinuxV2 psp-selinux-v2
K8sPSPAllowedUsers psp-pods-allowed-user-ranges
K8sPSPVolumeTypes psp-volume-types


--- 
This repo contains common policies needed in Pod Security Policy but implemented as Constraints and Constraint Templates with Gatekeeper.

A [Pod Security Policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) is a cluster-level resource that controls security
sensitive aspects of the pod specification. The `PodSecurityPolicy` objects define a set of conditions that a pod must run with in order to be accepted into the system, as well as defaults for the related fields.

An adminstrator can control the following by setting the field in PSP or by deploying the corresponding Gatekeeper constraint and constraint templates:

| Control Aspect                                    | Field Names in PSP                                                          | Gatekeeper Constraint and Constraint Template            |
| ------------------------------------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------- |
| Running of privileged containers                  | `privileged`                                                                | [privileged-containers](privileged-containers)           |
| Usage of host namespaces                          | `hostPID`, `hostIPC`                                                        | [host-namespaces](host-namespaces)                       |
| Usage of host networking and ports                | `hostNetwork`, `hostPorts`                                                  | [host-network-ports](host-network-ports)                 |
| Usage of volume types                             | `volumes`                                                                   | [volumes](volumes)                                       |
| Usage of the host filesystem                      | `allowedHostPaths`                                                          | [host-filesystem](host-filesystem)                       |
| White list of Flexvolume drivers                  | `allowedFlexVolumes`                                                        | [flexvolume-drivers](flexvolume-drivers)                 |
| Requiring the use of a read only root file system | `readOnlyRootFilesystem`                                                    | [read-only-root-filesystem](read-only-root-filesystem)   |
| The user and group IDs of the container           | `runAsUser`, `runAsGroup`, `supplementalGroups`, `fsgroup`                             | [users](users)<sup>\*</sup>
| Restricting escalation to root privileges         | `allowPrivilegeEscalation`, `defaultAllowPrivilegeEscalation`               | [allow-privilege-escalation](allow-privilege-escalation) |
| Linux capabilities                                | `defaultAddCapabilities`, `requiredDropCapabilities`, `allowedCapabilities` | [capabilities](capabilities)
| The SELinux context of the container              | `seLinux`                                                                   | [seLinux](selinux)                                       |
| The Allowed Proc Mount types for the container    | `allowedProcMountTypes`                                                     | [proc-mount](proc-mount)                                 |
| The AppArmor profile used by containers           | annotations                                                                 | [apparmor](apparmor)                                     |
| The seccomp profile used by containers            | annotations                                                                 | [seccomp](seccomp)                                       |
| The sysctl profile used by containers             | `forbiddenSysctls`,`allowedUnsafeSysctls`                                   | [forbidden-sysctls](forbidden-sysctls)                   |

<sup>\*</sup> For PSP rules that apply default value or mutations, Gatekeeper v3 currently cannot apply mutation.
