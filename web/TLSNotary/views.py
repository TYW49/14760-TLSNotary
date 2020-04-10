from django.shortcuts import render
from TLSNotary.notarize import *
from TLSNotary.reviewer import *

# Create your views here.
def generate_proof_action(request):
    context={}
    url = request.POST.get('url')
   
    if request.method == 'GET':
        return render(request, 'TLSNotary/generate_proof.html', context)
    
    try:
        ok, prooffile = notarize.generate(target, None)
        print(prooffile)
    except Exception as e:
        print(e)
        return render(request, 'TLSNotary/generate_proof.html', context)
    if ok:
        print('ok')
    else:
        print('not ok')
    return render(request, 'TLSNotary/generate_proof.html', context)
    
def verify_proof_action(request):
    context={}
    
    if request.method == 'GET':
        return render(request, 'TLSNotary/generate_proof.html', context)
    
    
    return render(request, 'TLSNotary/generate_proof.html', context)