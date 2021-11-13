from django.contrib import admin
from .models import ThunderbirdVulnerability
from .models import ChromiumVulnerability
from .models import FirefoxVulnerability
from .models import WordpressVulnerability
from .models import DrupalVulnerability
from .models import PidginVulnerability
from .models import ImpactedFilePatch
from .models import OpenMRSVulnerability
from .models import ResearchPaper
from .models import OfBizVulnerability
from .models import Concept
from .models import CVE, CWE, CVEProduct, CVEProductType, CVELanguage, Category
from .models import CodingTag, CodingTagWhere, CodingTagWhat, CodingTagHow

from ckeditor.widgets import CKEditorWidget
from dal import autocomplete


class VulnAdmin(admin.ModelAdmin):
    list_display = ('cve','cve_description','cve_type', 'is_pattern_analyzed','is_included','location_tag')
    list_filter  = ( 'is_pattern_analyzed', 'cve_type','is_included', )#'location_tag')

    readonly_fields = (
        # Vulnerability fieldset
        'vuln_id','cve_description', 'cve_urls','cwe_tag',
        # Files fieldset
        'affected_files',
        # Previous Analysis fieldset
        'commits_urls', 'bug_urls', 'is_included',
        'location_tag','concepts'
    )

    fieldsets = (
        ("Vulnerability", {
            'fields': ('vuln_id','cve_description','cwe_tag', 'cve_urls','is_included')
        }),
        ("Previous Analysis", {
            'fields': ('affected_files','commits_urls','bug_urls',)#'commit_url','bugtrack_url')
        }),
        ("Summarization Analysis", {
            'fields': ('context','problem', 'solution','cve_type', 'boundary_violation_rationale', 'is_pattern_analyzed')
        }),
        ("Coding", {
            'fields': ('location_tag','concepts')
        }),

        # ("Fix Analysis", {
        #     'fields': ('bugtrack_url','commit_url', )
        # }),


    )

    def get_form(self, request, obj=None, **kwargs):
        form = super(VulnAdmin, self).get_form(request, obj, **kwargs)
        # form.base_fields['location_tag'].queryset = form.base_fields['location_tag'].queryset.order_by('id')
        # form.base_fields["concepts"].widget = autocomplete.ModelSelect2Multiple(url='icsa2018:concept-autocomplete', attrs={ 'data-minimum-input-length': 3,})
        form.base_fields["context"].widget = CKEditorWidget()
        form.base_fields["problem"].widget = CKEditorWidget()
        form.base_fields["solution"].widget = CKEditorWidget()
        # print(form.base_fields)
        # form.base_fields['get_counterId'].queryset = CounterDetails.objects.all().order_by('-id')
        # form.base_fields['get_groupId'].queryset = CounterGroup.objects.all().order_by('-id')

        return form

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def vuln_id(self,obj):
        return "<a target='_blank' href='https://web.nvd.nist.gov/view/vuln/detail?vulnId="+ str(obj.cve.cve_id)+"'>"+str(obj.cve.cve_id)+"</a>"
    vuln_id.allow_tags = True
    vuln_id.short_description = 'CVE ID'

    def cwe_tag(self,obj):
        if obj.cve.cwe_tag:
            return obj.cve.cwe_tag
        return ""
    cwe_tag.admin_order_field = 'cwe_tag'
    cwe_tag.short_description = 'CWE Tag'


    def cve_description(self, obj):
        return obj.cve.description
    cve_description.allow_tags = True
    cve_description.short_description = 'Description'

    def cve_urls(self, obj):
        html_links = ""
        links = obj.cve.references.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link+"'>"+link+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    cve_urls.allow_tags = True
    cve_urls.short_description = 'References'

    def affected_files(self, obj):
        impacted_files = ImpactedFilePatch.objects.filter(cve = obj.cve_id)
        if len(impacted_files) == 0:
            return "---"
        html_links = "<table><thead><th>File Path</th><th>Total Added</th><th>Total Removed</th></thead><tbody>"
        for file in impacted_files:
            html_links += "<tr><td>"+file.file_path+"</td><td>"+str(file.total_added)+"</td><td>"+str(file.total_removed)+"</td></tr>"
        return html_links + "</tbody></table>"
    affected_files.allow_tags = True
    affected_files.short_description = 'Affected Files'

    def bug_urls(self, obj):
        # if Field is none, return empty string
        if obj.bugtrack_url is None: return '---'
        # if the URL is a buglist, the it does not split per comma
        if "buglist.cgi" in obj.bugtrack_url:
            return "<a target='_blank' href='"+obj.bugtrack_url.strip() +"'>"+obj.bugtrack_url.strip()+"</a>"

        # otherwise, split per comma
        html_links = ""
        links = obj.bugtrack_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    bug_urls.allow_tags = True
    bug_urls.short_description = 'Issue Tracking URL'

    def commits_urls(self, obj):
        # if Field is none, return empty string
        if obj.commit_url is None: return '---'

        html_links = ""
        links = obj.commit_url.split(",")
        for link in links:
            html_links += "<li><a target='_blank' href='"+link.strip()+"'>"+link.strip()+"</a></li>"
        return "<ul>" + html_links + "</ul>"
    commits_urls.allow_tags = True
    commits_urls.short_description = 'Commit URL(s)'


class CodingTagAdmin(admin.ModelAdmin):
    list_display = ('__str__',)
    # list_filter  = ( 'category',)

    def get_form(self, request, obj=None, **kwargs):
        form = super(CodingTagAdmin, self).get_form(request, obj, **kwargs)
        form.base_fields["description"].widget = CKEditorWidget()
        form.base_fields["consequences"].widget = CKEditorWidget()
        form.base_fields["mitigation"].widget = CKEditorWidget()
        return form


class PaperAdmin(admin.ModelAdmin):
    list_display = ('title','venue','year','search_query_id','assigned_to','match_our_criteria','exclusion_rationale','other_notes','is_analyzed')
    list_filter  = ( 'is_analyzed','assigned_to','match_our_criteria','search_query_id',)
    readonly_fields = (
        'assigned_to','title','author','year','library_source','abstract', 'keywords','abstract_html','venue','insights','url_html', 'num_pages',
    )

    fieldsets = (
        ("Paper", {
            'fields': ('title','author','year','library_source','abstract_html', 'keywords','url_html','venue','num_pages')
        }),
        ("Insights (These are automated findings to guide your analysis. However, DO NOT leverage these recommendations for your decision!)", {
            'fields': ('insights',)
        }),
        ("Analysis", {
            'fields': ('match_our_criteria','exclusion_rationale','overlapping_tags','other_notes','is_analyzed',)#'commit_url','bugtrack_url')
        }),
    )

    def url_html(self, obj):
        if obj.url is not None:
            return "<a href='"+obj.url+"'>"+obj.url+ "</a>"
        else:
            if obj.doi is not None:
                return "<a href='http://dx.doi.org/"+obj.doi+"'>"+obj.doi+ "</a>"
        return "---"
    url_html.allow_tags = True
    url_html.short_description = 'URL'

    def abstract_html(self, obj):
        color = "#FFFF00"
        if obj.abstract is not None:
            abstract = obj.abstract.replace("architecture","<span style='background-color: " +color+"'>architecture</span>")
            abstract = abstract.replace("plugin","<span style='background-color: " +color+"'>plugin</span>")
            abstract = abstract.replace("plug-in","<span style='background-color: " +color+"'>plug-in</span>")
            abstract = abstract.replace("vulnerability","<span style='background-color: " +color+"'>vulnerability</span>")
            abstract = abstract.replace("Vulnerability","<span style='background-color: " +color+"'>Vulnerability</span>")
            abstract = abstract.replace("Extensions","<span style='background-color: " +color+"'>Extensions</span>")
            abstract = abstract.replace("extensions","<span style='background-color: " +color+"'>extensions</span>")
            abstract = abstract.replace("Extension","<span style='background-color: " +color+"'>Extension</span>")
            abstract = abstract.replace("extension","<span style='background-color: " +color+"'>extension</span>")
            return abstract
        else: return ''

    abstract_html.allow_tags = True
    abstract_html.short_description = 'Abstract'


    def insights(self, obj):
        html = "<ul>"
        if obj.match_exclusion1():
            html += "<li style='list-style:square;'>It may be a short paper</li>"
        if obj.match_exclusion4():
            html += "<li style='list-style:square;'>It may not be in the domain of plug-and-play software architectures</li>"

        duplicated_papers = obj.find_any_duplicates()
        if len(duplicated_papers) > 0:
            html += "<li style='list-style:square;'> It may be a duplicated of the following papers: <ul style='margin-left: 20px;'>"
            for p in duplicated_papers:
                html += "<li style='list-style:circle;'>Paper #"+str(p.id)+" <a href='/admin/icsa2018/researchpaper/"+str(p.id)+"'>"+str(p)+"</a>. " + ("DOI="+p.doi if p.doi is not None else '')+ (" <span style='color:red;'>(<b>Not analyzed yet</b>)</span>" if p.is_analyzed == False else "<span style='color:green;'>(<b>Already analyzed</b>)</span>") + "</li>"
            html += "</ul></li>"

        html += "</ul>"

        """
        html = "<table>"
        html += "<thead style='background-color:lightgray;'><tr><td><b>Criteria</b></td><td><b>Insight</b></td></tr></thread>"
        html += "<tbody>"
        # html += "<tr><td>Inclusion #1 Full Paper</td><td> May be "+str(obj.match_exclusion1())+"</td></tr>"
        # html += "<tr><td>Inclusion #2 Focused on discussing security problems on a plug-and-play software architecture</td><td> May be "+str(obj.match_exclusion4())+"</td></tr>"
        html += "<tr><td>Exclusion #1 Books, position papers, short papers, tool demo papers, keynotes, reviews, tutorial summaries, and panel discussions</td><td> May be <b>"+str(obj.match_exclusion1())+"</b></td></tr>"
        html += "<tr><td>Exclusion #2 Not fully written in English</td><td> UNKNOWN </td></tr>"
        html += "<tr><td>Exclusion #3 Duplicated study</td><td> UNKNOWN </td></tr>"
        html += "<tr><td>Exclusion #4 Not focused on security problems on a plug-and-play software architecture (Violation of I2)</td><td> May be <b>"+str(obj.match_exclusion4())+"</b></td></tr>"
        html += "</tbody>"
        html += "</table>"
        """
        return html
        # return ''

    insights.allow_tags = True
    insights.short_description = 'Insights'


    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False



class CodingTagWhereInline(admin.TabularInline):
    model = CVE.wheres.through


class CodingTagWhereAdmin(admin.ModelAdmin):
    model = CodingTagWhere
    inlines = [
        CodingTagWhereInline,
    ]


class CodingTagWhatInline(admin.TabularInline):
    model = CVE.whats.through


class CodingTagWhatAdmin(admin.ModelAdmin):
    model = CodingTagWhat
    inlines = [
        CodingTagWhatInline,
    ]


class CodingTagHowInline(admin.TabularInline):
    model = CVE.hows.through


class CodingTagHowAdmin(admin.ModelAdmin):
    model = CodingTagHow
    inlines = [
        CodingTagHowInline,
    ]


class CWEInline(admin.TabularInline):
    model = CVE.cwe_tag.through


class CWEAdmin(admin.ModelAdmin):
    model = CWE
    inlines = [
        CWEInline,
    ]


class CVEProductInline(admin.TabularInline):
    model = CVE


class CVEProductAdmin(admin.ModelAdmin):
    inlines = [
        CVEProductInline,
    ]


class CVEProductTypeInline(admin.TabularInline):
    model = CVEProduct


class CVEProductTypeAdmin(admin.ModelAdmin):
    inlines = [
        CVEProductTypeInline,
    ]


class CVELanguageInline(admin.TabularInline):
    model = CVEProduct


class CVELanguageAdmin(admin.ModelAdmin):
    inlines = [
        CVELanguageInline,
    ]


# admin.site.register(CodingTagWhereAdmin)
# admin.site.register(ThunderbirdVulnerability,VulnAdmin)
# admin.site.register(ChromiumVulnerability,VulnAdmin)
# admin.site.register(FirefoxVulnerability,VulnAdmin)
# admin.site.register(WordpressVulnerability,VulnAdmin)
# admin.site.register(DrupalVulnerability,VulnAdmin)
# admin.site.register(PidginVulnerability,VulnAdmin)
# admin.site.register(OpenMRSVulnerability,VulnAdmin)
# admin.site.register(OfBizVulnerability,VulnAdmin)
# admin.site.register(Concept)
# admin.site.register(ResearchPaper,PaperAdmin)

# admin.site.register(CodingTag, CodingTagAdmin)
admin.site.register(CVE)
admin.site.register(Category)
admin.site.register(CodingTagWhere)#, CodingTagWhereAdmin)
admin.site.register(CodingTagWhat)#, CodingTagWhatAdmin)
admin.site.register(CodingTagHow)#, CodingTagHowAdmin)
admin.site.register(CVEProduct)#, CVEProductAdmin)
admin.site.register(CVEProductType)#, CVEProductTypeAdmin)
admin.site.register(CVELanguage)#, CVELanguageAdmin)
admin.site.register(CWE)#, CWEAdmin)
