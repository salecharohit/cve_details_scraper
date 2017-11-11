I have always been wanting to learn python , read many books , tried many online tutorials , but never did i made anything useful for myself or the online community.

As part of my new job profile , i was supposed to include all the vulnerabilities found during a particular month. So , i would visit cvedetails.com , filter the results by date,select the month, sort the CVSS score in the descending order and select only the vulnerabilities with a CVSS score greater than 7.0 ,select the table on the first page, copy in excel then click on link for 2nd page then copy and paste in excel and so on…

Now the problem with the CVE Details html structure is that , the description of the vulnerabilities gets copied into the next row. But i wanted everything in a column so i can filter and paste it into  report. I had to then cut all the description rows , filter the blank columns and then paste it into the column.

This is what it looked like when i would copy it directly from the CVE Details website.

![](http://www.rohitsalecha.com/wp-content/uploads/2016/01/cvedetailsscraper1-1.png)

Then another issue was that , the monthly view didnot provide version details nor the product details in a column format. I would then have to filter in the excel by keywords like “Google”,”Android”,”Windows” etc…

Phewwww… this was a very complicated job. So i though of automating this by writing a script in Python. I always wanted to learn it and develop something so i can save time from this manual work.

Here is the python code i developed and customized it to give me the excel in the required format.

Below is the screenshot of the excel which is created after my script runs.

![](http://www.rohitsalecha.com/wp-content/uploads/2016/01/cvedetailsscraper2.png)

Below is the screenshot showing the usage.

![](http://www.rohitsalecha.com/wp-content/uploads/2016/01/cvedetailsscraper3.png)

Small steps towards learning an amazing language below 🙂

NOTE: I have used Anaconda distribution of Python as Pandas library is not compiling in Activestate and other Python distros. So to run this you’ll need to install Anaconda.
