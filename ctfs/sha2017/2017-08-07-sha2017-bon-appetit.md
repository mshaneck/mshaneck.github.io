---
layout: default
title: CTF Solution Writeups - SHA2017 - Bon Appétit (Web 100)
category: ctf sha2017
tags: ctf sha2017
---

[SHA2017](https://ctf.sha2017.org/home) - Bon Appétit (Web 100)
------
The challenge starts with a link to a webpage for a restaurant. 

{% include image name="bon1-smaller.png" %}

First thing to do is view the source. One thing that is immediately apparent is the comment near the top of the page:

{% include image name="bon2.png" %} 

So we will need to look at access or error logs, if possible. Keep that in mind for later. Browsing around the website, it becomes apparent that there is one main page that is being used to load the individual content pages. This is evident by the url. For example to see the contact page, you load [http://bonappetit.stillhackinganyway.nl/?page=contact](http://bonappetit.stillhackinganyway.nl/?page=contact)

{% include image name="bon3.png" %} 


You can verify that it is loading that page directly by just browsing to that page:

{% include image name="bon4.png" %}

So it is not appending any file extension or anything. Good deal. Let’s see what sorts of files we can access. Browsing directly to [http://bonappetit.stillhackinganyway.nl/?page=/etc/passwd](http://bonappetit.stillhackinganyway.nl/?page=/etc/passwd) returns nothing. Let’s try a php filter: [http://bonappetit.stillhackinganyway.nl/?page=php://filter/resource=/etc/passwd](http://bonappetit.stillhackinganyway.nl/?page=php://filter/resource=/etc/passwd) 

{% include image name="bon5.png" %}

Good deal. Although, it is not clear that this file gets us. Let’s try to view the access logs. Trying to view /var/log/apache2/access.log gives us no results, but remember that comment? Maybe they are doing something different with the access logs. So let’s view the apache config file. Fortunately, they are using the default site config file: [http://bonappetit.stillhackinganyway.nl/?page=php://filter/resource=/etc/apache2/sites-enabled/000-default.conf](http://bonappetit.stillhackinganyway.nl/?page=php://filter/resource=/etc/apache2/sites-enabled/000-default.conf)

{% include image name="bon6.png" %}

We can see from here that they are using a custom log handler script and that script is located in the public website. So let’s take a look at that script and see what we can see there: [http://bonappetit.stillhackinganyway.nl/?page=php://filter/resource=/var/www/html/log.sh](http://bonappetit.stillhackinganyway.nl/?page=php://filter/resource=/var/www/html/log.sh)

{% include image name="bon7.png" %}

Ok, so it is keeping individual logs per client in the log directory. Let’s take a look.

{% include image name="bon8.png" %}

So we can see that it is keeping the log for my ip in this file and we can put content into that file, simply by requesting for various strings. So we can control some content that we can place on the site. But can we get it to execute? To get it to execute, what we would need to do is put php content into it and request it through the php interpreter. The file is a .log file, so it won’t execute, but as we saw in the beginning, the index.php file allows us to include files with no extensions. So let’s include this file. 

{% include image name="bon9.png" %}

Yes, so we can do it. It remains to inject some php code into it. Let’s try to get ls to execute. Trying to do this with a browser gets the special characters urlencoded and they don’t interpret, so I will skip ahead and say that you need to use netcat or something similar to get the characters in directly. 

{% include image name="bon10.png" %}

It says bad request, but that’s ok. It’s in the log. Now let’s reload that page from before and view the source.

{% include image name="bon11.png" %}

Aha! Looks like the flag is in suP3r_S3kr1t_Fl4G. Let’s get that file and see. Requesting it directly results in a forbidden message. So let’s include it.

{% include image name="bon12.png" %}

And there’s the flag!

So that’s the end. Although it bugged me that we could never see the source for index.php. That was the first file that I thought to view. I tried many other filters and encoding, including [http://bonappetit.stillhackinganyway.nl/?page=php://filter/convert.base64-encode/resource=/var/www/html/index.php](http://bonappetit.stillhackinganyway.nl/?page=php://filter/convert.base64-encode/resource=/var/www/html/index.php) but I never was able to view it. I assume that they were filtering for this filename to force the extra steps.

However, since we can now execute system commands, let’s see if we can see it.

{% include image name="bon13.png" %}

Success! And that explains why we could not see the index.php file. All in all, a fun challenge!


