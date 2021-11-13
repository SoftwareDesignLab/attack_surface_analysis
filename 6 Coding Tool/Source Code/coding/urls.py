from django.conf.urls import url

from .views import ChromiumPatternsView
from .views import FirefoxPatternsView
from .views import ThunderbirdPatternsView
from .views import PidginPatternsView
from .views import WordpressPatternsView
from .views import HomePageView
from .views import CVEPidginView
from .views import CVEThunderbirdView
from .views import CVEChromiumView
from .views import CVEFirefoxView
from .views import CVEWordpressView
from .views import CodingTagsView
from .views import TagsDetailView
from .views import ConceptAutocomplete
from .views import ViolationVisualization
from .views import ConceptsFrequencyView
from .views import SummariesView
from .views import ResearchPapersListView

urlpatterns = [

    # Chromium Web browser
    url(r'^chromium/findings/(?P<pk>[CVE\-0-9]+)$', CVEChromiumView.as_view(), name='cve-chromium-detail'),
    url(r'^chromium/cve-codes', SummariesView.as_view(), name='cve-chromium-codes'),
    url(r'^chromium/cve-summaries$', SummariesView.as_view(), name='cve-chromium-summaries'),
    url(r'^chromium/findings$', ChromiumPatternsView.as_view(), name='chromium-dataset'),

    # Firefox
    url(r'^firefox/findings/(?P<pk>[CVE\-0-9]+)$', CVEFirefoxView.as_view(), name='cve-firefox-detail'),
    url(r'^firefox/cve-codes', SummariesView.as_view(), name='cve-firefox-codes'),
    url(r'^firefox/cve-summaries$', SummariesView.as_view(), name='cve-firefox-summaries$'),
    url(r'^firefox/findings$', FirefoxPatternsView.as_view(), name='firefox-dataset'),

    # Thunderbird
    url(r'^thunderbird/findings/(?P<pk>[CVE\-0-9]+)$', CVEThunderbirdView.as_view(), name='cve-thunderbird-detail'),
    url(r'^thunderbird/cve-codes', SummariesView.as_view(), name='cve-thunderbird-codes'),
    url(r'^thunderbird/cve-summaries$', SummariesView.as_view(), name='cve-thunderbird-summaries$'),
    url(r'^thunderbird/findings$', ThunderbirdPatternsView.as_view(), name='thunderbird-dataset'),

    #Pidgin
    url(r'^pidgin/findings/(?P<pk>[CVE\-0-9]+)$', CVEPidginView.as_view(), name='cve-pidgin-detail'),
    url(r'^pidgin/cve-summaries$', SummariesView.as_view(), name='cve-pidgin-summaries'),
    url(r'^pidgin/cve-codes$', SummariesView.as_view(), name='cve-pidgin-codes'),
    url(r'^pidgin/findings$', PidginPatternsView.as_view(), name='pidgin-dataset'),


    #Wordpress
    url(r'^wordpress/findings/(?P<pk>[CVE\-0-9]+)$', CVEWordpressView.as_view(), name='cve-wordpress-detail'),
    url(r'^wordpress/cve-codes', SummariesView.as_view(), name='cve-wordpress-codes'),
    url(r'^wordpress/cve-summaries$', SummariesView.as_view(), name='cve-wordpress-summaries$'),
    url(r'^wordpress/findings$', WordpressPatternsView.as_view(), name='wordpress-dataset'),


    # OpenMRS
    url(r'^openmrs/cve-codes', SummariesView.as_view(), name='cve-openmrs-codes'),
    url(r'^openmrs/cve-summaries$', SummariesView.as_view(), name='cve-openmrs-summaries'),

    # OfBiz
    url(r'^ofbiz/cve-codes', SummariesView.as_view(), name='cve-ofbiz-codes'),
    url(r'^ofbiz/cve-summaries$', SummariesView.as_view(), name='cve-ofbiz-summaries'),


    # See all coding tags
    url(r'^tags/(?P<pk>[0-9]+)$', TagsDetailView.as_view(), name='tag-detail'),
    url(r'^tags$', CodingTagsView.as_view(), name='tags-list'),
    url(r'^tags/visualization$', ViolationVisualization.as_view(), name='tags-visualization'),

    # See all concepts
    url(r'^concepts$', ConceptsFrequencyView.as_view(), name='concepts-list'),


    # See all papers
    url(r'^papers$', ResearchPapersListView.as_view(), name='papers-list'),

    # Concepts auto complete view
    url(r'^concept-autocomplete/$',ConceptAutocomplete.as_view(create_field='name'),name='concept-autocomplete',),

    # Overview of the dataset
    url(r'^', HomePageView.as_view(), name='overview'),

]
