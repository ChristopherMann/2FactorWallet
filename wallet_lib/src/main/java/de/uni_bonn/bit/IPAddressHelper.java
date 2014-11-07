package de.uni_bonn.bit;

import org.apache.commons.net.util.SubnetUtils;

import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The class contains helper methods to work with IP addresses. This class is used to find an IP address which can be
 * used establish a network connection with another party.
 */
public class IPAddressHelper {
    /**
     * Returns a list of IP addresses that can be used to communicate with a peer on a
     * different machine. The IP addresses are in CIDR notation (e.g. 192.168.2.1/24).
     * @return
     */
    public static List<String> getAllUsableIPAddresses(){
        List<String> output = new ArrayList<String>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())){
                for(InterfaceAddress address : ni.getInterfaceAddresses()){
                    if(!address.getAddress().isMulticastAddress()
                            && !address.getAddress().isLinkLocalAddress()
                            && !address.getAddress().isLoopbackAddress()){
                        output.add(address.getAddress().getHostAddress() + "/" + address.getNetworkPrefixLength());
                    }
                }
            }
        }catch(SocketException e){

        }
        return output;
    }

    /**
     * Returns an IP address of this machine that is in the same subnet as one of the peerAddresses.
     * @param peerAddresses List of peer addresses in CIDR notation
     * @return Ip address as string without subnet information
     */
    public static String findFirstAddressInCommonNetwork(List<String> peerAddresses){
        List<String> myAddresses = getAllUsableIPAddresses();
        for(String myAdress : myAddresses){
            SubnetUtils.SubnetInfo subnetInfo = new SubnetUtils(myAdress).getInfo();
            for(String peerAddress : peerAddresses){
                String peerAddressWithoutSubnet = new SubnetUtils(peerAddress).getInfo().getAddress();
                if(subnetInfo.isInRange(peerAddressWithoutSubnet))
                    return peerAddressWithoutSubnet;
            }

        }
        return "";
    }
}
