Stavar Laurentiu-Cristian, Grupa 322CC

1. Implementation time: ~18h

2. Solved:

-- Forwarding process
-- Longest Prefix Match efficient
-- ICMP Protocol

3. Not solved:

-- ARP Protocol

4. Homework implemented in C

5. Solution explanation:

-- Alloc memory the routing table, I read it from the file and sort the routing
table, alloc the static arp table and read it from the file.
-- In a while loop I do the next steps.
    -- Read data from the network, and take the interface where data comes in.
    -- Check if the packet has the right size, if not drop it.
    -- Get the MAC & IP address of the interface.
    -- Check the type of the packet in a switch-case-default construction.
        -- If it's an IP packet,
            -- Get the IP header.
            -- Check if the router is the actual destination.
            -- If yes,
                -- Check if the packet is an ICMP packet.
                -- Get the ICMP header.
                -- Check if the ICMP packet is an echo request.
                -- Swap the MAC & IP addresses.
                -- Update the IP checksum.
                -- Create the ICMP echo reply.
                -- Send the packet to the network.
            -- If not, then the router is not the destination, so we need to
            forward the packet.
                -- Verify the checksum, if the checksums don't match, drop it.
                -- Check the TTL.
                -- If it's <= 0, then send ICMP packet with "Time exceeded".
                -- Else decrement the TTL.
                -- Find the best route.
                -- Check if the route exists.
                -- If not,
                    -- send an ICMP packet with "Destination unreachable".
                -- If yes,
                    -- Update the IP checksum with the formula from LAB 4.
                    -- Update the MAC addresses.
                    -- Send the packet to the network.
        -- If it's and ARP packet,
            -- I didn't have time to implement this part of the homework even though
            I wanted to. There are too many homeworks in a short period of time so
            it's basically imposible to finish all of them.
        -- Else, drop the packet.
    -- Free all the memory allocated.

6. Searching in the routing table:

-- For this part of the homework I choose to use the binary search instead of using
a trie. That's only because I find it easier this way and this is still better than
the liniar search.
-- My solution for searching in the routing table has a complexity of O(log n) which
is better than the O(n) complexity of a linear search.

7. No memory leaks:

-- Even tought it's not specified I tried to free all the memory I have allocated
during the implementation in order to reduce the memory leaks as much as possible.

╭━┳━╭━╭━╮╮
┃┈┈┈┣▅╋▅┫┃
┃┈┃┈╰━╰━━━━━━╮
╰┳╯┈┈┈┈┈┈┈┈┈◢▉◣
╲┃┈┈┈┈┈┈┈┈┈┈▉▉▉
╲┃┈┈┈┈┈┈┈┈┈┈◥▉◤
╲┃┈┈┈┈╭━┳━━━━╯
╲┣━━━━━━┫
