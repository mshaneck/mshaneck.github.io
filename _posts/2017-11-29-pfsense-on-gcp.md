---
layout: post
title: PfSense on Google Compute
comments: true
---

Recently I was trying to get PfSense installed and running on a GCP instance and I ran into a lot of trouble. This post is to document for my purposes what I did so I can repeat, but also to help others, if anyone else is trying to do it. The main issue is that the standard instructions out there for porting a VirtualBox image to GCP for Pfsense didn't work, and that is what is most prevalent when looking for answers.

What worked was what was found [here](https://groups.google.com/forum/#!topic/gce-discussion/tPYonu9dwbc). In summary, and in case that link happens to go away, what should be done is that instead of creating an installed image of Pfsense, just download the IMG version of the installer, rename it to disk.raw, compress with ```tar -Sczf``` and upload that to the storage bucket. 

The storage file can then be used to make an image. Use that image to create an instance that has a separate attached disk. It should boot into the installer, and using the interactive serial console (which needs to be enabled) install PfSense to the attached disk. Create a snapshot from that disk and create an instance from that snapshot. 

With that done, you should have a fully functional PfSense instance. Subsequent configuration will need to be done from the serial console to enable remote access, or otherwise configure how you need it configured. 