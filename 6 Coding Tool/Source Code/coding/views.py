from .models import ChromiumVulnerability
from .models import FirefoxVulnerability
from .models import ThunderbirdVulnerability
from .models import WordpressVulnerability
from .models import PidginVulnerability
from .models import OpenMRSVulnerability
from .models import OfBizVulnerability

from .models import CodingTag
from .models import Concept


from .models import ResearchPaper

from django.views.generic.list import ListView
from django.views.generic.detail import DetailView
from django.views.generic.base import TemplateView

from dal import autocomplete

def getProjectStats(proj_name, model_objs):
    total_cves = model_objs.filter(cve__published_date__lt='2016-04-01').count()
    total_included = model_objs.filter(is_included='1').count()
    total_analyzed = model_objs.filter(is_included='1',is_pattern_analyzed='1').count()
    total_plugins = model_objs.filter(is_included='1',cve_type = 'RELATED').count()

    return [ proj_name,total_cves,total_included,total_analyzed,total_plugins]



class HomePageView(TemplateView):
    template_name = "coding/overview.html"
    def get_context_data(self, **kwargs):
        context = super(HomePageView, self).get_context_data(**kwargs)
        context['vuln_types'] = ["# CVEs", "# Included","# Analyzed", "# Plugin-Related" ]
        context['statistics'] = [
            getProjectStats('Firefox', FirefoxVulnerability.objects),
            getProjectStats('Chromium', ChromiumVulnerability.objects),
            getProjectStats('Thunderbird', ThunderbirdVulnerability.objects),
            getProjectStats('Wordpress', WordpressVulnerability.objects),
            getProjectStats('Pidgin', PidginVulnerability.objects),
            # getProjectStats('Drupal', DrupalVulnerability.objects),
        ]


        # results = FirefoxVulnerability.objects.raw("SELECT COUNT(*) FROM icsa2018_firefoxvulnerability JOIN icsa2018_thunderbirdvulnerability USING(cve_id) where icsa2018_firefoxvulnerability.is_included = '1'")

        # context["overlaps"] = results[0]

        return context


class FirefoxPatternsView(ListView):
    model = FirefoxVulnerability
    template_name = "coding/cve_analysis.html"

    def get_context_data(self, **kwargs):
        context = super(FirefoxPatternsView, self).get_context_data(**kwargs)
        categories = dict()

        for entry in FirefoxVulnerability.objects.filter(is_included=1,cve_type = 'RELATED').order_by('-cve_id'):
            cve_type = entry.cve_type
            if cve_type != None and cve_type != '':
                if cve_type not in categories:
                    categories[cve_type] = []

                categories[cve_type].append(entry)

        context['categories'] = sorted(categories.items())
        context['case_study'] = "Firefox"
        return context

class CVEFirefoxView(DetailView):
    template_name = "coding/cve_detail.html"
    model = FirefoxVulnerability
    def get_context_data(self, **kwargs):
        context = super(CVEFirefoxView, self).get_context_data(**kwargs)
        context['project'] = "firefox"
        return context


class ChromiumPatternsView(ListView):
    model = ChromiumVulnerability
    template_name = "coding/cve_analysis.html"

    def get_context_data(self, **kwargs):
        context = super(ChromiumPatternsView, self).get_context_data(**kwargs)
        categories = dict()

        for entry in ChromiumVulnerability.objects.filter(is_included=1,cve_type = 'RELATED').order_by('-cve_id'):
            cve_type = entry.cve_type
            if cve_type != None and cve_type != '':
                if cve_type not in categories:
                    categories[cve_type] = []

                categories[cve_type].append(entry)

        context['categories'] = sorted(categories.items())
        context['case_study'] = "Chromium"
        return context

class CVEChromiumView(DetailView):
    template_name = "coding/cve_detail.html"
    model = ChromiumVulnerability
    def get_context_data(self, **kwargs):
        context = super(CVEChromiumView, self).get_context_data(**kwargs)
        context['project'] = "chromium"
        return context


class ThunderbirdPatternsView(ListView):
    model = ThunderbirdVulnerability
    template_name = "coding/cve_analysis.html"

    def get_context_data(self, **kwargs):
        context = super(ThunderbirdPatternsView, self).get_context_data(**kwargs)
        categories = dict()

        for entry in ThunderbirdVulnerability.objects.filter(is_included=1,cve_type = 'RELATED').order_by('-cve_id'):
            cve_type = entry.cve_type
            if cve_type != None and cve_type != '':
                if cve_type not in categories:
                    categories[cve_type] = []

                categories[cve_type].append(entry)

        context['categories'] = sorted(categories.items())
        context['case_study'] = "Thunderbird"
        return context

class CVEThunderbirdView(DetailView):
    template_name = "coding/cve_detail.html"
    model = ThunderbirdVulnerability
    def get_context_data(self, **kwargs):
        context = super(CVEThunderbirdView, self).get_context_data(**kwargs)
        context['project'] = "thunderbird"
        return context




class PidginPatternsView(ListView):
    model = PidginVulnerability
    template_name = "coding/cve_analysis.html"

    def get_context_data(self, **kwargs):
        context = super(PidginPatternsView, self).get_context_data(**kwargs)
        categories = dict()

        for entry in PidginVulnerability.objects.filter(is_included=1,cve_type = 'RELATED').order_by('-cve_id'):
            cve_type = entry.cve_type
            if cve_type != None and cve_type != '':
                if cve_type not in categories:
                    categories[cve_type] = []

                categories[cve_type].append(entry)

        context['categories'] = sorted(categories.items())
        context['case_study'] = "Pidgin"
        return context


class CVEPidginView(DetailView):
    template_name = "coding/cve_detail.html"
    model = PidginVulnerability
    def get_context_data(self, **kwargs):
        context = super(CVEPidginView, self).get_context_data(**kwargs)
        context['project'] = "pidgin"
        return context



class WordpressPatternsView(ListView):
    model = WordpressVulnerability
    template_name = "coding/cve_analysis.html"

    def get_context_data(self, **kwargs):
        context = super(WordpressPatternsView, self).get_context_data(**kwargs)
        categories = dict()

        for entry in WordpressVulnerability.objects.filter(is_included=1,cve_type = 'RELATED').order_by('-cve_id'):
            cve_type = entry.cve_type
            if cve_type != None and cve_type != '':
                if cve_type not in categories:
                    categories[cve_type] = []

                categories[cve_type].append(entry)

        context['categories'] = sorted(categories.items())
        context['case_study'] = "Wordpress"
        return context


class CVEWordpressView(DetailView):
    template_name = "coding/cve_detail.html"
    model = WordpressVulnerability
    def get_context_data(self, **kwargs):
        context = super(CVEWordpressView, self).get_context_data(**kwargs)
        context['project'] = "wordpress"
        return context



class TagsDetailView(DetailView):
    template_name = "coding/tag_detail.html"
    model = CodingTag
    def get_context_data(self, **kwargs):
        context = super(TagsDetailView, self).get_context_data(**kwargs)
        concepts = set()

        for vuln in self.object.chromiumvulnerability_set.all():
            for c in vuln.concepts.all():
                concepts.add(c.cwe_id.capitalize())
        for vuln in self.object.firefoxvulnerability_set.all():
            for c in vuln.concepts.all():
                concepts.add(c.cwe_id.capitalize())
        for vuln in self.object.pidginvulnerability_set.all():
            for c in vuln.concepts.all():
                concepts.add(c.cwe_id.capitalize())
        for vuln in self.object.firefoxvulnerability_set.all():
            for c in vuln.concepts.all():
                concepts.add(c.cwe_id.capitalize())
        for vuln in self.object.thunderbirdvulnerability_set.all():
            for c in vuln.concepts.all():
                concepts.add(c.cwe_id.capitalize())
        for vuln in self.object.wordpressvulnerability_set.all():
            for c in vuln.concepts.all():
                concepts.add(c.cwe_id.capitalize())

        # all_concepts = Concept.objects.all().filter()
        # for concept in all_concepts:
        #     if concept.chromiumvulnerability_set.all():

        # self.object.

        context["concepts"] = concepts
        return context


class CodingTagsView(TemplateView):
    template_name = "coding/cve_tags.html"

    def get_context_data(self, **kwargs):
        context = super(CodingTagsView, self).get_context_data(**kwargs)
        categories = dict()
        plugin_related_cves = [ entry for entry in ChromiumVulnerability.objects.filter(is_included=1,cve_type = 'RELATED').order_by('-cve_id') ]
        plugin_related_cves = plugin_related_cves + [ entry for entry in FirefoxVulnerability.objects.filter(is_included=1,cve_type = 'RELATED').order_by('-cve_id') ]
        plugin_related_cves = plugin_related_cves + [ entry for entry in PidginVulnerability.objects.filter(is_included=1,cve_type = 'RELATED').order_by('-cve_id') ]
        plugin_related_cves = plugin_related_cves + [ entry for entry in ThunderbirdVulnerability.objects.filter(is_included=1,cve_type = 'RELATED').order_by('-cve_id') ]
        plugin_related_cves = plugin_related_cves + [ entry for entry in WordpressVulnerability.objects.filter(is_included=1,cve_type = 'RELATED').order_by('-cve_id') ]

        # print(plugin_related_cves)
        for entry in plugin_related_cves:
            location_tag = entry.location_tag
            if location_tag != None:
                location_tag = str(entry.location_tag)
                if location_tag not in categories:
                    categories[location_tag] = []
                categories[location_tag].append(entry)

        print(categories)



        context['categories'] = sorted(categories.items())

        return context





class ConceptAutocomplete(autocomplete.Select2QuerySetView):
    def get_queryset(self):
        # Don't forget to filter out results depending on the visitor !
        if not self.request.user.is_authenticated() or not self.request.user.is_staff:
            return Concept.objects.none()

        qs = Concept.objects.all()

        if self.q:
            # qs = qs.filter(name__istartswith=self.q)
            qs = qs.filter(name__icontains=self.q)

        return qs



class ViolationVisualization(TemplateView):
    template_name = "coding/visualization.html"


class ConceptsFrequencyView(ListView):
    model = Concept
    template_name = "coding/concepts_frequency.html"

    def get_context_data(self, **kwargs):
        context = super(ConceptsFrequencyView, self).get_context_data(**kwargs)
        # results = dict()
        # for concept in context["object_list"]:
        #     total = concept.chromiumvulnerability_set.all().count() + concept.firefoxvulnerability_set.all().count()
        #     results[concept.id] = total

        # context["total"] = results

        return context


class SummariesView(ListView):
    model = PidginVulnerability
    template_name = "coding/cve_summaries.html"

    def get_template_names(self):
        template_name = self.template_name
        if 'cve-summaries' in self.request.get_full_path():
            template_name = "coding/cve_summaries.html"
        if 'cve-codes' in self.request.get_full_path():
            template_name = "coding/cve_codes.html"
        return [template_name,]

    def get_context_data(self, **kwargs):
        context = super(SummariesView, self).get_context_data(**kwargs)
        if 'pidgin' in self.request.get_full_path():
            context['cves'] = PidginVulnerability.objects.filter(is_included=1,location_tag__isnull=False).order_by('-cve_id')
            context['case_study'] = "Pidgin"
        if 'wordpress' in self.request.get_full_path():
            context['cves'] = WordpressVulnerability.objects.filter(is_included=1,location_tag__isnull=False).order_by('-cve_id')
            context['case_study'] = "WordPress"

        if 'firefox' in self.request.get_full_path():
            thund_cves = {}
            for cve in ThunderbirdVulnerability.objects.filter(is_included=1,location_tag__isnull=False).order_by('-cve_id'):
                thund_cves[cve.cve_id] = cve

            all_cves = []
            firefox_cves = FirefoxVulnerability.objects.filter(is_included=1,location_tag__isnull=False).order_by('-cve_id')
            for cve in firefox_cves:
                if cve.cve_id in thund_cves: all_cves.append(thund_cves[cve.cve_id])
                else: all_cves.append(cve)

            context['cves'] = all_cves

            context['case_study'] = "Firefox"
        if 'thunderbird' in self.request.get_full_path():
            context['cves'] = ThunderbirdVulnerability.objects.filter(is_included=1,location_tag__isnull=False).order_by('-cve_id')
            context['case_study'] = "Thunderbird"
        if 'ofbiz' in self.request.get_full_path():
            context['cves'] = OfBizVulnerability.objects.filter(is_included=1,location_tag__isnull=False).order_by('-cve_id')
            context['case_study'] = "OfBiz"
        if 'openmrs' in self.request.get_full_path():
            context['cves'] = OpenMRSVulnerability.objects.filter(is_included=1,location_tag__isnull=False).order_by('-cve_id')
            context['case_study'] = "OpenMRS"
        if 'chromium' in self.request.get_full_path():
            context['cves'] = ChromiumVulnerability.objects.filter(is_included=1,location_tag__isnull=False).order_by('-cve_id')
            context['case_study'] = "Chromium"

        return context



class ResearchPapersListView(ListView):
    model = ResearchPaper
#    template_name = "coding/papers.html"

    def get_context_data(self, **kwargs):
        context = super(ResearchPapersListView, self).get_context_data(**kwargs)
        context['papers'] = ResearchPaper.objects.filter(match_our_criteria="Yes").order_by('-year')
        return context

