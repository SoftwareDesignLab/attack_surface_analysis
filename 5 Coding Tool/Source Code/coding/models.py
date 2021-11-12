from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.core.validators import RegexValidator
from django.db.models import F
from django.db.models.functions import Lower, Substr

# from tagging.registry import register
# import tagulous.models

# Vulnerabilities types: (plugin-related,unrelated (non-related to plugins),vague,external,deprected and duplicated)
VULN_TYPE_PLUGIN = ("RELATED","PLUGIN-RELATED")
VULN_TYPE_UNRELATED = ("NON-RELATED","NON-RELATED TO PLUGINS/EXTENSIONS/ADD-ONs")
VULN_TYPE_VAGUE =("VAGUE","VAGUE")
VULN_TYPE_EXTERNAL = ("EXTERNAL","EXTERNAL")
VULN_TYPE_DEPRECATED =("DEPRECATED","DEPRECATED")
VULN_TYPE_DUPLICATED =("DUPLICATED","DUPLICATED")


VULN_TYPES_CHOICES = (
    VULN_TYPE_PLUGIN,
    VULN_TYPE_UNRELATED,
    VULN_TYPE_VAGUE,
    VULN_TYPE_EXTERNAL,
    VULN_TYPE_DEPRECATED,
    VULN_TYPE_DUPLICATED
)

ARCH_TAGS = (
    ('I','Tactic Implementation'),
    ('D','Deterioration'),
    ('BD','Inappropriate Design Decision'),
    ('MD', 'Missing Design Decision'),
)

# Used to guide the coding process (in order to derive the core categories)
class Concept(models.Model):
    name = models.CharField(max_length=200)
    def __str__(self):
        return self.name


# Language for Product for CVEs
@python_2_unicode_compatible
class CVELanguage(models.Model):
    name = models.CharField(max_length=100, primary_key=True, default='')

    def __str__(self):
        return "CVELanguage-" + self.name

    class Meta:
        ordering = ('name',)


# Product type for CVEs
@python_2_unicode_compatible
class CVEProductType(models.Model):
    title = models.CharField(max_length=100, default='')
    description = models.TextField()

    def __str__(self):
        return "CVEProductType-" + str(self.id) + " " + self.title

    class Meta:
        ordering = ('title',)


# Product name for CVEs
@python_2_unicode_compatible
class CVEProduct(models.Model):
    title = models.CharField(max_length=100, primary_key=True, default='')
    description = models.TextField()
    product_type = models.ForeignKey(CVEProductType, blank=False, null=True)#default=None)
    language = models.ForeignKey(CVELanguage, blank=False, default=None)

    def __str__(self):
        return "CVEProduct-" + self.title

    class Meta:
        ordering = ('title',)


# CWE Tags used by NVD
@python_2_unicode_compatible
class CWE(models.Model):
    cwe_id = models.CharField(max_length=100, default='', primary_key=True, validators=[RegexValidator(r"CWE-\d{3}")])
    description = models.TextField()
    notes = models.TextField(blank=True, null=True)
    # abstraction = models.CharField(max_length=100,blank=True, null=True)

    def __str__(self):
        return self.cwe_id

    class Meta:
        ordering = ('cwe_id',)


# Shared descriptions for where, what, and how for coding tags
@python_2_unicode_compatible
class CodingTagWhere(models.Model):
    title = models.CharField(max_length=200, default='', primary_key=True)
    description = models.TextField(blank=False)

    def __str__(self):
        return "CodingTagWhere: " + self.title

    class Meta:
        ordering = ('title',)


@python_2_unicode_compatible
class CodingTagWhat(models.Model):
    title = models.CharField(max_length=200, default='', primary_key=True)
    description = models.TextField(blank=False)

    def __str__(self):
        return "CodingTagWhat: " + self.title

    class Meta:
        ordering = ('title',)


@python_2_unicode_compatible
class CodingTagHow(models.Model):
    title = models.CharField(max_length=200, default='', primary_key=True)
    description = models.TextField(blank=False)

    def __str__(self):
        return "CodingTagHow: " + self.title

    class Meta:
        ordering = ('title',)


# Vulnerability (CVE instance)
@python_2_unicode_compatible
class CVE(models.Model):
    cve_id = models.CharField(max_length=15, primary_key=True, validators=[RegexValidator(r"CVE-\d{4}-\d{4,7}")])
    product = models.ForeignKey(CVEProduct, null=True)#default=None)
    # cwe_tag = models.ForeignKey(CWE, blank=False, default=None)
    cwe_tag = models.ManyToManyField(CWE, default=None)
    description = models.TextField(blank=False, default=None)
    # notes = models.TextField(blank=True, null=True)
    published_date = models.DateField()
    # references = models.TextField(blank=True, null=True)

    wheres = models.ManyToManyField(CodingTagWhere, blank=False, default=None)
    whats = models.ManyToManyField(CodingTagWhat, blank=False, default=None)
    hows = models.ManyToManyField(CodingTagHow, blank=False, default=None)

    notes = models.TextField(blank=False, default='', null=True)
    consequences = models.TextField(blank=True, default='')
    mitigation = models.TextField(blank=True, default='')

    def __str__(self):
        return self.cve_id


class Category(models.Model):
    title = models.CharField(max_length=200, default='', primary_key=True)
    description = models.TextField(blank=False, default=None)

    wheres = models.ManyToManyField(CodingTagWhere, blank=True, default=None)
    whats = models.ManyToManyField(CodingTagWhat, blank=True, default=None)
    hows = models.ManyToManyField(CodingTagHow, blank=True, default=None)

    def __str__(self):
        return self.title


# Core categories
@python_2_unicode_compatible
class CodingTag(models.Model):
    # category = models.CharField(max_length=50,default='')
    title = models.CharField(max_length=200,default='')

    where = models.ForeignKey(CodingTagWhere, blank=False, default=None)
    what = models.ForeignKey(CodingTagWhat, blank=False, default=None)
    how = models.ForeignKey(CodingTagHow, blank=False, default=None)
    cves = models.ManyToManyField(CVE, default=None)

    description = models.TextField(blank=False, default='')
    consequences = models.TextField(blank=False, default='')
    mitigation = models.TextField(blank=False, default='')

    def __str__(self):
        # return self.category + " > " + self.title
        return "Tag #" + str(self.id) + " " + self.title


# Impacted File
class ImpactedFilePatch(models.Model):
    file_path = models.TextField()
    cve = models.ForeignKey(CVE)
    case_study = models.CharField(max_length=30)
    total_added = models.IntegerField()
    total_removed = models.IntegerField()

# Vulnerabilities related to the Chromium Project
class ChromiumVulnerability(models.Model):
    class Meta: verbose_name_plural = "Chromium Vulnerabilities"
    cve = models.OneToOneField(CVE,primary_key=True)
    commit_url = models.TextField(max_length=5000,blank=True, null=True)
    bugtrack_url = models.TextField(max_length=5000,blank=True, null=True)

    # New fields for ICSA 2018
    cve_type =models.CharField(max_length=20,choices=VULN_TYPES_CHOICES,blank=True, null=True)
    context = models.TextField(blank=True, null=True)
    problem = models.TextField(blank=True, null=True)
    solution = models.TextField(blank=True, null=True)
    is_pattern_analyzed = models.BooleanField(default=False)
    boundary_violation_rationale = models.TextField(blank=True, null=True, verbose_name="What it is your rationale behind your decision of being/not being a trust boundary violation?")
    # is_boundary_violation = models.BooleanField(default=False) # can be removed
    is_included = models.BooleanField(default=False)
    location_tag = models.ForeignKey(CodingTag,blank=True,null=True)
    concepts = models.ManyToManyField(Concept,blank=True)

    def commits_urls_html(self):
        html_links = ""
        if self.commit_url is None: return "---"
        links = self.commit_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    commits_urls_html.allow_tags = True
    commits_urls_html.short_description = 'Commit URL(s)'

    def bugtrack_urls_html(self):
        # if Field is none, return empty string
        if self.bugtrack_url is None: return '---'
        # if the URL is a buglist, the it does not split per comma
        if "buglist.cgi" in self.bugtrack_url:
            return "<a target='_blank' href='"+self.bugtrack_url.strip() +"'>"+self.bugtrack_url.strip()+"</a>"

        # otherwise, split per comma
        html_links = ""
        links = self.bugtrack_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    bugtrack_urls_html.allow_tags = True
    bugtrack_urls_html.short_description = 'Issue Tracking URL'


    def references_html(self):
        html_links = ""
        links = self.cve.references.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link+"'>"+link+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    references_html.allow_tags = True
    references_html.short_description = 'References'

    def __str__(self):
        return self.cve_id


# Vulnerabilities related to the Thunderbird Project
class ThunderbirdVulnerability(models.Model):
    class Meta: verbose_name_plural = "Thunderbird Vulnerabilities"
    cve = models.OneToOneField(CVE,primary_key=True)
    commit_url = models.TextField(max_length=5000,blank=True, null=True)
    bugtrack_url = models.TextField(max_length=5000,blank=True, null=True)

    # New fields for ICSA 2018
    cve_type =models.CharField(max_length=20,choices=VULN_TYPES_CHOICES,blank=True, null=True)
    context = models.TextField(blank=True, null=True)
    problem = models.TextField(blank=True, null=True)
    solution = models.TextField(blank=True, null=True)
    is_pattern_analyzed = models.BooleanField(default=False)
    boundary_violation_rationale = models.TextField(blank=True, null=True, verbose_name="What it is your rationale behind your decision of being/not being a trust boundary violation?")
    # is_boundary_violation = models.BooleanField(default=False) # can be removed
    is_included = models.BooleanField(default=False)
    location_tag = models.ForeignKey(CodingTag,blank=True,null=True)
    concepts = models.ManyToManyField(Concept,blank=True)

    def commits_urls_html(self):
        html_links = ""
        if self.commit_url is None: return "---"
        links = self.commit_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    commits_urls_html.allow_tags = True
    commits_urls_html.short_description = 'Commit URL(s)'

    def bugtrack_urls_html(self):
        # if Field is none, return empty string
        if self.bugtrack_url is None: return '---'
        # if the URL is a buglist, the it does not split per comma
        if "buglist.cgi" in self.bugtrack_url:
            return "<a target='_blank' href='"+self.bugtrack_url.strip() +"'>"+self.bugtrack_url.strip()+"</a>"

        # otherwise, split per comma
        html_links = ""
        links = self.bugtrack_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    bugtrack_urls_html.allow_tags = True
    bugtrack_urls_html.short_description = 'Issue Tracking URL'

    def references_html(self):
        html_links = ""
        links = self.cve.references.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link+"'>"+link+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    references_html.allow_tags = True
    references_html.short_description = 'References'

    def __str__(self):
        return self.cve_id



# Vulnerabilities related to the Firefox Project
class FirefoxVulnerability(models.Model):
    class Meta: verbose_name_plural = "Firefox Vulnerabilities"
    cve = models.OneToOneField(CVE,primary_key=True)
    commit_url = models.TextField(max_length=5000,blank=True, null=True)
    bugtrack_url = models.TextField(max_length=5000,blank=True, null=True)

    # New fields for ICSA 2018
    cve_type =models.CharField(max_length=20,choices=VULN_TYPES_CHOICES,blank=True, null=True)
    context = models.TextField(blank=True, null=True)
    problem = models.TextField(blank=True, null=True)
    solution = models.TextField(blank=True, null=True)
    is_pattern_analyzed = models.BooleanField(default=False)
    boundary_violation_rationale = models.TextField(blank=True, null=True, verbose_name="What it is your rationale behind your decision of being/not being a trust boundary violation?")
    # is_boundary_violation = models.BooleanField(default=False) # can be removed
    is_included = models.BooleanField(default=False)
    location_tag = models.ForeignKey(CodingTag,blank=True,null=True)
    concepts = models.ManyToManyField(Concept,blank=True)

    def commits_urls_html(self):
        html_links = ""
        if self.commit_url is None: return "---"
        links = self.commit_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    commits_urls_html.allow_tags = True
    commits_urls_html.short_description = 'Commit URL(s)'

    def bugtrack_urls_html(self):
        # if Field is none, return empty string
        if self.bugtrack_url is None: return '---'
        # if the URL is a buglist, the it does not split per comma
        if "buglist.cgi" in self.bugtrack_url:
            return "<a target='_blank' href='"+self.bugtrack_url.strip() +"'>"+self.bugtrack_url.strip()+"</a>"

        # otherwise, split per comma
        html_links = ""
        links = self.bugtrack_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    bugtrack_urls_html.allow_tags = True
    bugtrack_urls_html.short_description = 'Issue Tracking URL'

    def references_html(self):
        html_links = ""
        links = self.cve.references.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link+"'>"+link+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    references_html.allow_tags = True
    references_html.short_description = 'References'

    def __str__(self):
        return self.cve_id


# Vulnerabilities related to the Drupal Project
class DrupalVulnerability(models.Model):
    class Meta: verbose_name_plural = "Drupal Vulnerabilities"
    cve = models.OneToOneField(CVE,primary_key=True)
    commit_url = models.TextField(max_length=5000,blank=True, null=True)
    bugtrack_url = models.TextField(max_length=5000,blank=True, null=True)

    # New fields for ICSA 2018
    cve_type =models.CharField(max_length=20,choices=VULN_TYPES_CHOICES,blank=True, null=True)
    context = models.TextField(blank=True, null=True)
    problem = models.TextField(blank=True, null=True)
    solution = models.TextField(blank=True, null=True)
    is_pattern_analyzed = models.BooleanField(default=False)
    boundary_violation_rationale = models.TextField(blank=True, null=True, verbose_name="What it is your rationale behind your decision of being/not being a trust boundary violation?")
    # is_boundary_violation = models.BooleanField(default=False) # can be removed
    is_included = models.BooleanField(default=False)
    location_tag = models.ForeignKey(CodingTag,blank=True,null=True)
    concepts = models.ManyToManyField(Concept,blank=True)


    def commits_urls_html(self):
        html_links = ""
        if self.commit_url is None: return "---"
        links = self.commit_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    commits_urls_html.allow_tags = True
    commits_urls_html.short_description = 'Commit URL(s)'

    def bugtrack_urls_html(self):
        # if Field is none, return empty string
        if self.bugtrack_url is None: return '---'
        # if the URL is a buglist, the it does not split per comma
        if "buglist.cgi" in self.bugtrack_url:
            return "<a target='_blank' href='"+self.bugtrack_url.strip() +"'>"+self.bugtrack_url.strip()+"</a>"

        # otherwise, split per comma
        html_links = ""
        links = self.bugtrack_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    bugtrack_urls_html.allow_tags = True
    bugtrack_urls_html.short_description = 'Issue Tracking URL'

    def references_html(self):
        html_links = ""
        links = self.cve.references.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link+"'>"+link+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    references_html.allow_tags = True
    references_html.short_description = 'References'

    def __str__(self):
        return self.cve_id


# Vulnerabilities related to the Wordpress Project
class WordpressVulnerability(models.Model):
    class Meta: verbose_name_plural = "Wordpress Vulnerabilities"
    cve = models.OneToOneField(CVE,primary_key=True)
    commit_url = models.TextField(max_length=5000,blank=True, null=True)
    bugtrack_url = models.TextField(max_length=5000,blank=True, null=True)

    # New fields for ICSA 2018
    cve_type =models.CharField(max_length=20,choices=VULN_TYPES_CHOICES,blank=True, null=True)
    context = models.TextField(blank=True, null=True)
    problem = models.TextField(blank=True, null=True)
    solution = models.TextField(blank=True, null=True)
    is_pattern_analyzed = models.BooleanField(default=False)
    boundary_violation_rationale = models.TextField(blank=True, null=True, verbose_name="What it is your rationale behind your decision of being/not being a trust boundary violation?")
    # is_boundary_violation = models.BooleanField(default=False) # can be removed
    is_included = models.BooleanField(default=False)
    location_tag = models.ForeignKey(CodingTag,blank=True,null=True)
    concepts = models.ManyToManyField(Concept,blank=True)

    def commits_urls_html(self):
        html_links = ""
        if self.commit_url is None: return "---"
        links = self.commit_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    commits_urls_html.allow_tags = True
    commits_urls_html.short_description = 'Commit URL(s)'

    def bugtrack_urls_html(self):
        # if Field is none, return empty string
        if self.bugtrack_url is None: return '---'
        # if the URL is a buglist, the it does not split per comma
        if "buglist.cgi" in self.bugtrack_url:
            return "<a target='_blank' href='"+self.bugtrack_url.strip() +"'>"+self.bugtrack_url.strip()+"</a>"

        # otherwise, split per comma
        html_links = ""
        links = self.bugtrack_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    bugtrack_urls_html.allow_tags = True
    bugtrack_urls_html.short_description = 'Issue Tracking URL'


    def references_html(self):
        html_links = ""
        links = self.cve.references.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link+"'>"+link+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    references_html.allow_tags = True
    references_html.short_description = 'References'


    def __str__(self):
        return self.cve_id


# Vulnerabilities related to the Wordpress Project
class PidginVulnerability(models.Model):
    class Meta: verbose_name_plural = "Pidgin Vulnerabilities"
    cve = models.OneToOneField(CVE,primary_key=True)
    commit_url = models.TextField(max_length=5000,blank=True, null=True)
    bugtrack_url = models.TextField(max_length=5000,blank=True, null=True)

    # New fields for ICSA 2018
    cve_type =models.CharField(max_length=20,choices=VULN_TYPES_CHOICES,blank=True, null=True)
    context = models.TextField(blank=True, null=True)
    problem = models.TextField(blank=True, null=True)
    solution = models.TextField(blank=True, null=True)
    is_pattern_analyzed = models.BooleanField(default=False)
    boundary_violation_rationale = models.TextField(blank=True, null=True, verbose_name="What it is your rationale behind your decision of being/not being a trust boundary violation?")
    # is_boundary_violation = models.BooleanField(default=False) # can be removed
    is_included = models.BooleanField(default=False)
    location_tag = models.ForeignKey(CodingTag,blank=True,null=True)
    concepts = models.ManyToManyField(Concept,blank=True)

    def commits_urls_html(self):
        html_links = ""
        if self.commit_url is None: return "---"
        links = self.commit_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    commits_urls_html.allow_tags = True
    commits_urls_html.short_description = 'Commit URL(s)'

    def bugtrack_urls_html(self):
        # if Field is none, return empty string
        if self.bugtrack_url is None: return '---'
        # if the URL is a buglist, the it does not split per comma
        if "buglist.cgi" in self.bugtrack_url:
            return "<a target='_blank' href='"+self.bugtrack_url.strip() +"'>"+self.bugtrack_url.strip()+"</a>"

        # otherwise, split per comma
        html_links = ""
        links = self.bugtrack_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    bugtrack_urls_html.allow_tags = True
    bugtrack_urls_html.short_description = 'Issue Tracking URL'

    def references_html(self):
        html_links = ""
        links = self.cve.references.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link+"'>"+link+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    references_html.allow_tags = True
    references_html.short_description = 'References'

    def __str__(self):
        return self.cve_id



# Vulnerabilities related to the Wordpress Project
class OfBizVulnerability(models.Model):
    class Meta: verbose_name_plural = "Apache OfBiz Vulnerabilities"
    cve = models.OneToOneField(CVE,primary_key=True)
    commit_url = models.TextField(max_length=5000,blank=True, null=True)
    bugtrack_url = models.TextField(max_length=5000,blank=True, null=True)

    # New fields for ICSA 2018
    cve_type =models.CharField(max_length=20,choices=VULN_TYPES_CHOICES,blank=True, null=True)
    context = models.TextField(blank=True, null=True)
    problem = models.TextField(blank=True, null=True)
    solution = models.TextField(blank=True, null=True)
    is_pattern_analyzed = models.BooleanField(default=False)
    boundary_violation_rationale = models.TextField(blank=True, null=True, verbose_name="What it is your rationale behind your decision of being/not being a trust boundary violation?")
    # is_boundary_violation = models.BooleanField(default=False) # can be removed
    is_included = models.BooleanField(default=False)
    location_tag = models.ForeignKey(CodingTag,blank=True,null=True)
    concepts = models.ManyToManyField(Concept,blank=True)

    def commits_urls_html(self):
        html_links = ""
        if self.commit_url is None: return "---"
        links = self.commit_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    commits_urls_html.allow_tags = True
    commits_urls_html.short_description = 'Commit URL(s)'

    def bugtrack_urls_html(self):
        # if Field is none, return empty string
        if self.bugtrack_url is None: return '---'
        # if the URL is a buglist, the it does not split per comma
        if "buglist.cgi" in self.bugtrack_url:
            return "<a target='_blank' href='"+self.bugtrack_url.strip() +"'>"+self.bugtrack_url.strip()+"</a>"

        # otherwise, split per comma
        html_links = ""
        links = self.bugtrack_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    bugtrack_urls_html.allow_tags = True
    bugtrack_urls_html.short_description = 'Issue Tracking URL'

    def references_html(self):
        html_links = ""
        links = self.cve.references.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link+"'>"+link+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    references_html.allow_tags = True
    references_html.short_description = 'References'

    def __str__(self):
        return self.cve_id

# Vulnerabilities related to the Wordpress Project
class OpenMRSVulnerability(models.Model):
    class Meta: verbose_name_plural = "OpenMRS Vulnerabilities"
    cve = models.OneToOneField(CVE,primary_key=True)
    commit_url = models.TextField(max_length=5000,blank=True, null=True)
    bugtrack_url = models.TextField(max_length=5000,blank=True, null=True)

    # New fields for ICSA 2018
    cve_type =models.CharField(max_length=20,choices=VULN_TYPES_CHOICES,blank=True, null=True)
    context = models.TextField(blank=True, null=True)
    problem = models.TextField(blank=True, null=True)
    solution = models.TextField(blank=True, null=True)
    is_pattern_analyzed = models.BooleanField(default=False)
    boundary_violation_rationale = models.TextField(blank=True, null=True, verbose_name="What it is your rationale behind your decision of being/not being a trust boundary violation?")
    # is_boundary_violation = models.BooleanField(default=False) # can be removed
    is_included = models.BooleanField(default=False)
    location_tag = models.ForeignKey(CodingTag,blank=True,null=True)
    concepts = models.ManyToManyField(Concept,blank=True)

    def commits_urls_html(self):
        html_links = ""
        if self.commit_url is None: return "---"
        links = self.commit_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    commits_urls_html.allow_tags = True
    commits_urls_html.short_description = 'Commit URL(s)'

    def bugtrack_urls_html(self):
        # if Field is none, return empty string
        if self.bugtrack_url is None: return '---'
        # if the URL is a buglist, the it does not split per comma
        if "buglist.cgi" in self.bugtrack_url:
            return "<a target='_blank' href='"+self.bugtrack_url.strip() +"'>"+self.bugtrack_url.strip()+"</a>"

        # otherwise, split per comma
        html_links = ""
        links = self.bugtrack_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    bugtrack_urls_html.allow_tags = True
    bugtrack_urls_html.short_description = 'Issue Tracking URL'

    def references_html(self):
        html_links = ""
        links = self.cve.references.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link+"'>"+link+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    references_html.allow_tags = True
    references_html.short_description = 'References'

    def __str__(self):
        return self.cve_id




class ResearchPaper(models.Model):
    assigned_to = models.CharField(max_length=15,blank=True, null=True)
    search_query_id = models.CharField(max_length=4)
    url = models.CharField(max_length=2000,blank=True, null=True)
    publication_type = models.CharField(max_length=2000,blank=True, null=True)
    doi = models.CharField(max_length=200,blank=True, null=True)
    year = models.CharField(max_length=5)
    author = models.CharField(max_length=5000,blank=True,null=True)
    title = models.CharField(max_length=1000,blank=True,null=True)
    venue = models.CharField(max_length=100,blank=True,null=True)
    abstract = models.CharField(max_length=100,blank=True, null=True)
    keywords = models.CharField(max_length=100,blank=True, null=True)
    num_pages = models.IntegerField(default=0)
    library_source = models.CharField(max_length=100)
    match_our_criteria = models.CharField(max_length=3,choices=(("Yes","Yes"),("No","No"),),blank=True, null=True)
    is_analyzed = models.BooleanField(default=False)
    exclusion_rationale = models.TextField(blank=True, null=True)
    overlapping_tags = models.TextField(blank=True, null=True)
    other_notes = models.TextField(blank=True, null=True)

    # Tests for Exclusion1: Short papers, etc
    def match_exclusion1(self):
        return self.num_pages > 0 and self.num_pages < 3


    # Tests for Exclusion2: Do not talk about plug-and-play software architectures
    def match_exclusion4(self):
        has_keywords = False
        has_security = False

        plugin_keywords=['plugin','plug-in','browser extension',]
        if self.abstract is not None:
            if any(word in self.abstract.lower() for word in plugin_keywords):
                has_keywords =  True
        if any(word in self.title.lower() for word in plugin_keywords):
            has_keywords = True

        security_keywords=['vulnerabilit','security',]
        if self.abstract is not None:
            if any(word in self.abstract.lower() for word in security_keywords):
                has_security =  True
        if any(word in self.title.lower() for word in security_keywords):
            has_security = True

        # It may match the exclusion criteria if the paper don't talk about security or plug-in
        return not (has_keywords and has_security)


    def find_any_duplicates(self):
        duplicated_doi = ResearchPaper.objects.filter(doi=self.doi).exclude(id=self.id).exclude(doi__isnull=True)
        duplicated_title = ResearchPaper.objects.filter(title=self.title).exclude(id=self.id)
        duplicated_ids = set()
        papers = []
        for paper in duplicated_doi:
            if paper.id not in duplicated_ids :#and paper.doi is not None:
                duplicated_ids.add(paper.id)
                papers.append(paper)

        for paper in duplicated_title:
            if paper.id not in duplicated_ids:
                duplicated_ids.add(paper.id)
                papers.append(paper)


        return papers

    def __str__(self):
        return "(" + self.year + ") " + self.title
